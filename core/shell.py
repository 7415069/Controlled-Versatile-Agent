"""
统一底座（Universal Shell）v2 — 接入持久化记忆 + LiteLLM
"""

import json
import time
import uuid
from typing import Dict, List, Optional

from core.audit import AuditLogger
from core.escalation import EscalationManager
from core.llm_adapter import (
  LLMAdapter,
  convert_assistant_with_tools_to_litellm,
  convert_tool_result_to_litellm,
)
from core.manifest import load_manifest, RoleManifest
from core.memory import MemoryStore
from core.permissions import PermissionChecker
from tools.catalog import build_tools


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
    self._escalation = EscalationManager(
        policy=self._manifest.escalation_policy,
        permission_checker=self._perm,
        audit_log_fn=self._logger.log,
    )
    self._tools = build_tools(self._manifest.capabilities, self._escalation.check)
    self._llm = LLMAdapter(model=model)
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
          system_prompt=self._manifest.identity_prompt,
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

    tool = self._tools.get(tool_name)
    if not tool:
      result = {
        "status": "error",
        "error_code": "TOOL_NOT_AVAILABLE",
        "message": f"工具 `{tool_name}` 未注册，当前可用: {list(self._tools.keys())}",
      }
    else:
      try:
        result = tool.execute(**tool_input)
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


def _hash(text: str) -> str:
  import hashlib
  return hashlib.sha256(text.encode()).hexdigest()[:16]
