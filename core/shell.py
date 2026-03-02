"""
统一底座（Universal Shell）v3 — 接入持久化记忆 + LiteLLM
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
from core.tool import build_tools, err


class UniversalShell:
  """
  CVA 唯一的业务无关运行时 v2。
  新增：
    - 持久化上下文记忆（MemoryStore），跨 session 恢复对话历史
    - LiteLLM 适配层，一行切换任意模型提供商
    - 自动记忆脱水机制：针对旧的巨大代码文件自动提取大纲以节省 Token
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

    self._escalation = EscalationManager(
        policy=self._manifest.escalation_policy,
        permission_checker=self._perm,
        audit_log_fn=self._logger.log,
        llm_call_fn=None,
    )
    self._tools = build_tools(self._manifest.capabilities, self._escalation.check)

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

  # ── 主循环 ─────────────────────────────────────────────────

  def _run_loop(self):
    while self._iteration < self._max_iterations:
      self._iteration += 1
      tok = self._memory.token_estimate()
      print(f"\n[CVA] ── 第 {self._iteration} 轮推理（≈{tok:,} tokens）──")

      # ─── 核心修改：发送脱水后的记忆 ───
      messages_to_send = self._prepare_dehydrated_messages(keep_last_n=4)

      response = self._llm.chat(
          messages=messages_to_send,
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

      self._memory.append(
          convert_assistant_with_tools_to_litellm(response.text, response.tool_calls)
      )

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

      if response.finish_reason == "tool_calls" and response.tool_calls:
        for tc in response.tool_calls:
          tr = self._dispatch_tool(tc.name, tc.input, tc.id)
          self._memory.append(tr)
        continue

      if response.finish_reason == "length":
        print("[CVA] ⚠️  输出截断，继续推理...")
        continue

      break

    self.stop("loop_end")

  # ── 工具分发 ───────────────────────────────────────────────

  def _dispatch_tool(self, tool_name: str, tool_input: Dict, call_id: str) -> Dict:
    t0 = time.time()
    print(f"\n🔧 {tool_name}({json.dumps(tool_input, ensure_ascii=False)[:120]})")

    enriched_input = {**tool_input, "_context_summary": self._context_summary()}
    tool = self._tools.get(tool_name)
    if not tool:
      result = err("TOOL_NOT_AVAILABLE", f"工具 `{tool_name}` 未注册")
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

  # ── 辅助方法 ──

  def _print_banner(self):
    m = self._manifest
    sid = self._memory.session_id
    status = f"恢复（{len(self._memory.messages)} 条历史）" if self._memory.messages else "新建"
    print("\n" + "╔" + "═" * 60 + "╗")
    print(f"║  受控百变智能体 (CVA) v2  —  启动中{' ' * 24}║")
    print("╠" + "═" * 60 + "╣")
    print(f"║  角色       : {m.role_name:<46}║")
    print(f"║  模型       : {self._model:<46}║")
    print(f"║  Session    : {sid[:36]:<46}║")
    print(f"║  记忆状态   : {status:<46}║")
    print("╚" + "═" * 60 + "╝")

  def _get_effective_system_prompt(self) -> str:
    base_prompt = self._manifest.identity_prompt
    current_perms = self._perm.snapshot()
    law_prompt = textwrap.dedent(f"""
      ### ⚠️ 运行环境与权限准则 (必读) ⚠️
      1. 你当前运行在“受控百变智能体 (CVA)”底座上。
      2. 读: {current_perms['read']} | 写: {current_perms['write']} | 命令: {current_perms['shell']}
      3. 越权申请必须提供详尽的 'reason'。
      4. 💡 提示：为了节省 Token，底座会自动对旧的消息历史进行“脱水”处理（只保留代码大纲）。
      5. 如果你需要重新查看某个文件的细节，请再次调用 read_file。
      """).strip()
    return f"{base_prompt}\n\n{law_prompt}"

  # ─── 记忆脱水核心逻辑 ───

  def _prepare_dehydrated_messages(self, keep_last_n: int = 4) -> List[Dict]:
    """对历史消息进行智能脱水：保留元数据，压缩旧的巨大代码文件内容"""
    raw_msgs = self._memory.messages
    dehydrated_msgs = []
    threshold_idx = len(raw_msgs) - keep_last_n

    for i, msg in enumerate(raw_msgs):
      new_msg = msg.copy()
      # 识别工具返回的消息（CVA v2 兼容模式下 role 为 user）
      if i < threshold_idx and msg.get("role") == "user":
        content_str = msg.get("content", "")
        if "artifact_type" in content_str and '"file_content"' in content_str:
          try:
            # 去除可能存在的 [TOOL_RESULT] 前缀
            json_part = content_str.split("\n", 1)[1] if content_str.startswith("[TOOL_RESULT") else content_str
            data = json.loads(json_part)

            if data.get("artifact_type") == "file_content" and len(data.get("content", "")) > 1500:
              # ── 执行脱水 ──
              outline = self._extract_python_outline(data["content"])
              data["metadata"]["is_full_text"] = False
              data["content"] = f"[DEHYDRATED] 全文已压缩。代码大纲：\n{outline}\n(如需修改，请重读全文)"

              # 重新组装内容
              prefix = "[TOOL_RESULT (Dehydrated)]\n" if content_str.startswith("[TOOL_RESULT") else ""
              new_msg["content"] = prefix + json.dumps(data, ensure_ascii=False)
          except:
            pass
      dehydrated_msgs.append(new_msg)
    return dehydrated_msgs

  def _extract_python_outline(self, code: str) -> str:
    """提取 Python 大纲，保留类/函数定义及缩进"""
    outline = []
    lines = code.split('\n')
    for line in lines:
      stripped = line.strip()
      if stripped.startswith(('def ', 'class ')):
        # 保留原始行（包含其缩进）
        outline.append(line)
    return "\n".join(outline[:40])  # 最多保留 40 行大纲

  # ── 其它逻辑 ──

  def _make_pre_screen_call(self, req) -> PreScreenResult:
    output_schema = {
      "type": "object",
      "properties": {
        "is_necessary": {"type": "boolean"},
        "reasoning": {"type": "string"},
        "alternative": {"type": "string"},
      },
      "required": ["is_necessary", "reasoning", "alternative"],
    }
    user_message = f"评估必要性：\n工具: {req.tool_name}\n路径: {req.requested_path}\n理由: {req.reason}"
    result = self._llm.structured_chat(
        messages=[{"role": "user", "content": user_message}],
        system_prompt="你是 CVA 安全模块。判断越权请求是否必须。",
        output_schema=output_schema,
        function_name="submit_judgment",
        function_description="提交判断结果",
        max_tokens=512,
    )
    if result is None:
      return PreScreenResult(is_necessary=True, reasoning="调用失败，保守放行。")
    return PreScreenResult(is_necessary=bool(result.get("is_necessary")), reasoning=str(result.get("reasoning")), alternative=str(result.get("alternative")))

  def _context_summary(self, last_n: int = 6) -> str:
    msgs = self._memory.messages
    recent = msgs[-last_n:] if len(msgs) > last_n else msgs
    lines = []
    for m in recent:
      role = m.get("role", "")
      if role not in ("user", "assistant"):
        continue
      text = str(m.get("content", ""))
      if text:
        lines.append(f"[{'用户' if role == 'user' else '助手'}] {text[:150]}")
    return "\n".join(lines)


def _hash(text: str) -> str:
  import hashlib
  return hashlib.sha256(text.encode()).hexdigest()[:16]
