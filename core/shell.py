"""
统一底座（Universal Shell）v2 — 接入持久化记忆 + LiteLLM
"""

import json
import textwrap
import time
import uuid
from typing import Dict, List, Optional

from core.audit import AuditLogger
from core.escalation import EscalationManager, PreScreenResult
from core.llm_adapter import (
  LLMAdapter,
  convert_assistant_with_tools_to_litellm,
  convert_tool_result_to_litellm,
)
from core.manifest import load_manifest, RoleManifest
from core.memory import MemoryStore
from core.permissions import PermissionChecker
from core.tool import build_tools


class UniversalShell:
  """
  CVA 唯一的业务无关运行时 v2。
  新增：
    - 持久化上下文记忆（MemoryStore），跨 session 恢复对话历史
    - LiteLLM 适配层，一行切换任意模型提供商
  """

  def __init__(
      self,
      manifest_path: str,
      model: str = "claude-opus-4-5",
      log_dir: str = "./audit-logs",
      memory_dir: str = "./memory",
      session_id: Optional[str] = None,
      max_iterations: int = 100,
      max_memory_messages: int = 200,
      max_token_budget: int = 80000,
  ):
    self._instance_id = str(uuid.uuid4())
    self._model = model
    self._max_iterations = max_iterations
    self._iteration = 0
    self._start_time = None

    self._manifest: RoleManifest = load_manifest(manifest_path)
    self._logger = AuditLogger(log_dir, self._instance_id, self._manifest.role_name)
    self._perm = PermissionChecker(self._manifest.init_permissions)

    # EscalationManager 先不带 llm_call_fn（LLM 还未初始化）
    self._escalation = EscalationManager(
        policy=self._manifest.escalation_policy,
        permission_checker=self._perm,
        audit_log_fn=self._logger.log,
        llm_call_fn=None,
    )
    self._tools = build_tools(self._manifest.capabilities, self._escalation.check)

    # LLM 初始化后立即注入二次确认函数
    self._llm = LLMAdapter(model=model)
    self._escalation.set_llm_call_fn(self._make_pre_screen_call)

    self._memory = MemoryStore(
        memory_dir=memory_dir,
        role_name=self._manifest.role_name,
        session_id=session_id,
        max_messages=max_memory_messages,
        max_token_budget=max_token_budget,
    )

  # ── 生命周期 ───────────────────────────────────────────────

  def start(self):
    self._start_time = time.time()
    self._print_banner()

    self._logger.log("AGENT_START", {
      "model": self._model,
      "session_id": self._memory.session_id,
      "manifest_version": self._manifest.version,
      "init_permissions": self._perm.snapshot(),
      "capabilities": self._manifest.capabilities,
      "resumed": len(self._memory.messages) > 0,
      "history_messages": len(self._memory.messages),
    })

    if self._memory.messages:
      print(f"\n[CVA] 已恢复 {len(self._memory.messages)} 条历史对话记录。")
      print(f"[CVA] 首条消息预览: {self._memory.summary_line()}")

    print("\n[CVA] 请输入任务（直接回车继续上次对话）：")
    try:
      user_task = input("> ").strip()
    except EOFError:
      user_task = ""

    if user_task:
      self._memory.append({"role": "user", "content": user_task})
      self._logger.log("HUMAN_INPUT", {"content_hash": _hash(user_task)})
    elif not self._memory.messages:
      default = "请先探索当前工作目录，然后等待进一步指示。"
      self._memory.append({"role": "user", "content": default})

    self._run_loop()

  def stop(self, reason: str = "normal"):
    duration = round(time.time() - (self._start_time or time.time()), 2)
    self._logger.log("AGENT_STOP", {
      "stop_reason": reason,
      "session_id": self._memory.session_id,
      "total_iterations": self._iteration,
      "duration_seconds": duration,
      "total_memory_messages": len(self._memory.messages),
      "token_estimate": self._memory.token_estimate(),
      "final_whitelist": self._perm.snapshot(),
    })
    self._memory.close()
    print(f"\n[CVA] Agent 已停止（{reason}，耗时 {duration}s）")
    print(f"[CVA] Session ID: {self._memory.session_id}")
    print(f"[CVA] 下次恢复: python cva.py --manifest <role> --session {self._memory.session_id}")

  # ── 主循环 ─────────────────────────────────────────────────

  def _run_loop(self):
    while self._iteration < self._max_iterations:
      self._iteration += 1
      tok = self._memory.token_estimate()
      print(f"\n[CVA] ── 第 {self._iteration} 轮推理（≈{tok:,} tokens）──")

      response = self._llm.chat(
          messages=self._memory.messages,
          system_prompt=self._get_effective_system_prompt(),
          tools=self._build_tool_specs(),
          max_tokens=self._manifest.max_tokens,
      )

      if response.finish_reason == "error":
        print(f"[CVA] ❌ LLM 错误: {response.text}")
        self._logger.log("LLM_API_ERROR", {"error": response.text})
        break

      if response.usage:
        self._logger.log("LLM_USAGE", {"iteration": self._iteration, **response.usage})

      if response.text and response.text.strip():
        print(f"\n🤖 {response.text}")

      # 持久化 assistant 消息
      self._memory.append(
          convert_assistant_with_tools_to_litellm(response.text, response.tool_calls)
      )

      # 任务完成
      if response.finish_reason == "stop":
        print("\n[CVA] ✅ 任务完成")
        try:
          cont = input("\n[CVA] 继续对话？（直接回车退出）: ").strip()
        except EOFError:
          cont = ""
        if cont:
          self._memory.append({"role": "user", "content": cont})
          self._logger.log("HUMAN_INPUT", {"content_hash": _hash(cont)})
          continue
        break

      # 工具调用
      if response.finish_reason == "tool_calls" and response.tool_calls:
        for tc in response.tool_calls:
          tr = self._dispatch_tool(tc.name, tc.input, tc.id)
          self._memory.append(tr)
        continue

      # length truncation
      if response.finish_reason == "length":
        print("[CVA] ⚠️  输出截断，继续推理...")
        continue

      print(f"[CVA] 结束，finish_reason={response.finish_reason}")
      break

    if self._iteration >= self._max_iterations:
      print(f"\n[CVA] ⚠️  已达最大迭代次数 {self._max_iterations}。")
      self._logger.log("MAX_ITERATIONS_REACHED", {"max": self._max_iterations})

    self.stop("loop_end")

  # ── 工具分发 ───────────────────────────────────────────────

  def _dispatch_tool(self, tool_name: str, tool_input: Dict, call_id: str) -> Dict:
    t0 = time.time()
    print(f"\n🔧 {tool_name}({json.dumps(tool_input, ensure_ascii=False)[:120]})")

    # 注入对话摘要，供 EscalationManager LLM 二次确认使用
    enriched_input = {**tool_input, "_context_summary": self._context_summary()}

    tool = self._tools.get(tool_name)
    if not tool:
      result = {
        "status": "error",
        "error_code": "TOOL_NOT_AVAILABLE",
        "message": f"工具 `{tool_name}` 未注册，当前可用: {list(self._tools.keys())}",
      }
    else:
      try:
        result = tool.execute(**enriched_input)
      except Exception as e:
        result = {"status": "error", "error_code": "UNEXPECTED_ERROR", "message": str(e)}

    duration_ms = round((time.time() - t0) * 1000)
    self._logger.log("TOOL_CALL", {
      "tool_name": tool_name,
      "target": tool_input.get("path") or tool_input.get("command") or tool_input.get("url", ""),
      "status": result.get("status"),
      "duration_ms": duration_ms,
    })

    icon = "✅" if result.get("status") == "ok" else "❌"
    print(f"   {icon} {json.dumps(result, ensure_ascii=False)[:200]}")

    return convert_tool_result_to_litellm(call_id, json.dumps(result, ensure_ascii=False))

  def _build_tool_specs(self) -> List[Dict]:
    return [t.to_api_spec() for t in self._tools.values()]

  # ── Banner ─────────────────────────────────────────────────

  def _print_banner(self):
    m = self._manifest
    sid = self._memory.session_id
    resumed = len(self._memory.messages) > 0
    status = f"恢复（{len(self._memory.messages)} 条历史）" if resumed else "新建"
    print("\n" + "╔" + "═" * 60 + "╗")
    print(f"║  受控百变智能体 (CVA) v2  —  启动中{' ' * 24}║")
    print("╠" + "═" * 60 + "╣")
    print(f"║  角色       : {m.role_name:<46}║")
    print(f"║  模型       : {self._model:<46}║")
    print(f"║  Session    : {sid[:36]:<46}║")
    print(f"║  记忆状态   : {status:<46}║")
    print(f"║  工具数量   : {len(self._tools):<46}║")
    print("╠" + "═" * 60 + "╣")
    print(f"║  读权限     : {str(m.init_permissions.read)[:46]:<46}║")
    print(f"║  写权限     : {str(m.init_permissions.write)[:46]:<46}║")
    print(f"║  命令白名单 : {str(m.init_permissions.shell)[:46]:<46}║")
    print("╚" + "═" * 60 + "╝")

  def _get_effective_system_prompt(self) -> str:
    """
    将 Manifest 中的灵魂注入，并叠加受控底座的‘法律条文’
    """
    base_prompt = self._manifest.identity_prompt

    # 获取当前权限白名单的快照，告诉模型它现在能干什么
    current_perms = self._perm.snapshot()

    # 法律条文（底座强制注入）
    law_prompt = textwrap.dedent(f"""
      ### ⚠️ 运行环境与权限准则 (必读) ⚠️
      1. 你当前运行在“受控百变智能体 (CVA)”底座上。
      2. 你当前的【初始合法领地】为:
         - 读: {current_perms['read']}
         - 写: {current_perms['write']}
         - 命令: {current_perms['shell']}
      3. 如果你需要操作领地之外的资源，你必须调用工具并提供详尽的 'reason'。
      4. 你的 reason 会被直接展示给人类导师（老板）。如果理由不充分，老板会拒绝你的提权申请。
      5. 严禁猜测路径。请先使用 list_directory 探索环境，看准了再发起越权申请。
      """).strip()
    return f"{base_prompt}\n\n{law_prompt}"


def _hash(text: str) -> str:
  import hashlib
  return hashlib.sha256(text.encode()).hexdigest()[:16]


# ── LLM 二次确认（结构化输出版）────────────────────────────

def _make_pre_screen_call(self, req) -> PreScreenResult:
  """
  供 EscalationManager 调用。
  使用 structured_chat（function calling）强制获取结构化判断，零正则解析。

  输出 Schema 通过 function_calling 约束，LLM 必须填充每个字段：
    - is_necessary: bool
    - reasoning: str（1-2句判断依据）
    - alternative: str（不必须时的替代方案）
  """
  # from core.escalation import PreScreenResult

  # 二次确认的输出 JSON Schema
  output_schema = {
    "type": "object",
    "properties": {
      "is_necessary": {
        "type": "boolean",
        "description": (
          "true = 这个越权操作是完成任务的绝对必要条件，在白名单内找不到等价资源；"
          "false = 可以跳过或用已有权限内的资源替代"
        ),
      },
      "reasoning": {
        "type": "string",
        "description": "1-2句话说明判断依据，需具体指出为什么必须或不必须",
      },
      "alternative": {
        "type": "string",
        "description": "如果 is_necessary=false，给出具体可行的替代方案；is_necessary=true 时填空字符串",
      },
    },
    "required": ["is_necessary", "reasoning", "alternative"],
  }

  # 把 EscalationRequest 的关键信息拼入 user 消息
  user_message = (
    f"请判断以下越权访问请求的必要性：\n\n"
    f"工具: {req.tool_name}\n"
    f"目标路径/命令: {req.requested_path}\n"
    f"权限类型: {req.permission_type}\n"
    f"Agent 理由: {req.reason or '（未说明）'}\n\n"
    f"当前任务上下文（最近对话）:\n{req.context_summary or '（无上下文）'}"
  )

  result = self._llm.structured_chat(
      messages=[{"role": "user", "content": user_message}],
      system_prompt=(
        "你是受控百变智能体（CVA）的安全审计模块。\n"
        "你的唯一职责：客观判断一个 AI Agent 的越权访问请求是否是完成当前任务的绝对必要条件。\n\n"
        "判断标准：\n"
        "- 必须 (is_necessary=true)：没有此资源任务完全无法推进，且白名单内无等价替代\n"
        "- 不必须 (is_necessary=false)：可跳过/用已有权限替代/调整策略规避，或与任务核心目标关联度低"
      ),
      output_schema=output_schema,
      function_name="submit_necessity_judgment",
      function_description="提交对越权访问请求必要性的判断结果",
      max_tokens=512,
  )

  if result is None:
    # structured_chat 失败 → 保守策略
    return PreScreenResult(
        is_necessary=True,
        reasoning="structured_chat 调用失败，保守升级到人类审批。",
    )

  return PreScreenResult(
      is_necessary=bool(result.get("is_necessary", True)),
      reasoning=str(result.get("reasoning", "")),
      alternative=str(result.get("alternative", "")),
  )


def _context_summary(self, last_n: int = 6) -> str:
  """提取最近 N 轮 user/assistant 文本摘要，跳过 tool_result。"""
  msgs = self._memory.messages
  recent = msgs[-last_n:] if len(msgs) > last_n else msgs
  lines = []
  for m in recent:
    role = m.get("role", "")
    if role not in ("user", "assistant"):
      continue
    content = m.get("content", "")
    if isinstance(content, list):
      text = " ".join(
          b.get("text", "") or b.get("content", "")
          for b in content
          if isinstance(b, dict) and b.get("type") in ("text", None)
      ).strip()
    else:
      text = str(content or "").strip()
    if text:
      lines.append(f"[{'用户' if role == 'user' else '助手'}] {text[:150]}")
  return "\n".join(lines)
