"""
统一底座（Universal Shell）v3.6

修复内容：
  P2-6: _periodic_cleanup 是永不退出的 daemon 线程，stop() 没有通知它退出的机制。
        多次实例化 UniversalShell（如测试场景）会积累孤立线程。
        → 使用 threading.Event(_stop_event) 优雅停止清理线程。
  串联修复：
        - build_tools() 传入 self._safe_input 作为 input_fn（修复 AskHumanTool 裸input）
        - EscalationManager 传入 input_fn=self._safe_input（修复 console_approval 裸input）
        - EscalationManager 接受 gui_approval_fn（修复子线程创建 Tkinter）
        - shell.py 本身不直接调用 tkinter，由 cv_agent.py 主线程注入 gui_approval_fn
"""

import json
import os
import sys
import textwrap
import threading
import time
import unicodedata
import uuid
from typing import Callable, Dict, List, Optional

from brtech_cva.core.audit import AuditLogger
from brtech_cva.core.config import cva_settings
from brtech_cva.core.escalation import EscalationManager, PreScreenResult
from brtech_cva.core.llm_adapter import (
  LLMAdapter,
  convert_assistant_with_tools_to_litellm,
  convert_tool_result_to_litellm,
)
from brtech_cva.core.logger import sys_logger
from brtech_cva.core.manifest import load_manifest, RoleManifest
from brtech_cva.core.memory import MemoryStore
from brtech_cva.core.permissions import PermissionChecker
from brtech_cva.core.tool import build_tools


class UniversalShell:
  """CVA 唯一的业务无关运行时 v3.6"""

  def __init__(
      self,
      manifest_path: str,
      model: str = "claude-opus-4-5",
      audit_log_dir: str = cva_settings.audit_settings.log_dir,
      memory_dir: str = cva_settings.memory_settings.data_dir,
      session_id: Optional[str] = None,
      max_iterations: int = 100,
      max_memory_messages: int = 200,
      max_token_budget: int = 80000,
      # 修复 P0-3：接受主线程弹窗回调，而非 use_gui 布尔值
      # GUI 模式由 cv_agent.py 在 _run_agent 里注入，CLI 模式传 None
      gui_approval_fn: Optional[Callable] = None,
  ):
    self._instance_id = str(uuid.uuid4())
    self._model = model
    self._max_iterations = max_iterations
    self._iteration = 0
    self._start_time = None

    # 修复 P2-6：停止事件，用于优雅退出 cleanup 线程
    self._stop_event = threading.Event()

    self._manifest: RoleManifest = load_manifest(manifest_path)
    self._logger = AuditLogger(self._instance_id, self._manifest.role_name, audit_log_dir)
    self._perm = PermissionChecker(self._manifest.init_permissions)

    self._escalation = EscalationManager(
        policy=self._manifest.escalation_policy,
        permission_checker=self._perm,
        audit_log_fn=self._logger.log,
        llm_call_fn=None,
        # 修复 P0-3 & P2-5：统一注入 input_fn 和 gui_approval_fn
        gui_approval_fn=gui_approval_fn,
        input_fn=self._safe_input,
    )

    # 修复 P2-4：向 build_tools 传入 self._safe_input，
    # AskHumanTool 将使用它替代裸 input()
    self._tools = build_tools(
        self._manifest.capabilities,
        self._escalation.check,
        input_fn=self._safe_input,
    )

    self._llm = LLMAdapter(model=model)
    self._escalation.set_llm_call_fn(self._make_pre_screen_call)

    os.makedirs(memory_dir, exist_ok=True)

    self._memory = MemoryStore(
        memory_dir=memory_dir,
        role_name=self._manifest.role_name,
        session_id=session_id,
        max_messages=max_memory_messages,
        max_token_budget=max_token_budget,
        model=model,
    )

    self._cleanup_thread: Optional[threading.Thread] = None
    self._dehydration_cache: Dict[int, Dict] = {}
    self._last_dehydration_time = 0.0
    self._DEHYDRATION_CACHE_TTL = cva_settings.memory_settings.dehydration_cache_ttl

  # ── 生命周期 ───────────────────────────────────────────────

  def start(self):
    os.makedirs(cva_settings.audit_settings.log_dir, exist_ok=True)
    self._start_time = time.time()
    self._print_banner()

    self._logger.log("AGENT_START", {
      "model": self._model,
      "session_id": self._memory.session_id,
      "resumed": len(self._memory.messages) > 0,
    })

    # 修复 P2-6：启动时重置停止事件，确保可以多次 start/stop
    self._stop_event.clear()
    self._cleanup_thread = threading.Thread(
        target=self._periodic_cleanup,
        daemon=True,
        name=f"CVA-Cleanup-{self._instance_id[:8]}"
    )
    self._cleanup_thread.start()

    print("\n[CVA] 请输入任务（直接回车继续上次对话）：")
    user_task = self._safe_input("> ")

    if user_task:
      self._memory.append({"role": "user", "content": user_task})
    elif not self._memory.messages:
      self._memory.append({"role": "user", "content": "请先探索当前工作目录。"})

    self._run_loop()

  def _periodic_cleanup(self):
    """
    每 5 分钟清理过期权限。

    修复 P2-6：使用 _stop_event.wait(timeout) 替代 time.sleep()，
    stop() 调用时立即通知线程退出，不需要等待下一个 sleep 周期结束。
    """
    while not self._stop_event.is_set():
      # wait 返回 True 表示 event 被 set（收到停止信号），直接退出
      if self._stop_event.wait(timeout=300):
        break
      try:
        self._escalation.cleanup_expired_permissions()
      except Exception as e:
        print(f"[CVA] ⚠️ 自动清理线程异常: {e}")

  def stop(self, reason: str = "normal"):
    # 修复 P2-6：通知 cleanup 线程退出
    self._stop_event.set()

    duration = round(time.time() - (self._start_time or time.time()), 2)
    self._memory.close()
    print(f"\n[CVA] Agent 已停止（{reason}，耗时 {duration}s）")

  # ── 主循环 ─────────────────────────────────────────────────

  def _run_loop(self):
    consecutive_failures = 0
    MAX_RETRIES = cva_settings.llm_settings.max_retries

    sys_logger.info(f"开始任务循环。Session ID: {self._memory.session_id}")
    while self._iteration < self._max_iterations:
      last_msg = self._memory.messages[-1] if self._memory.messages else {}
      is_in_middle_of_tools = last_msg.get("role") == "assistant" and "tool_calls" in last_msg

      if self._iteration > 0 and self._iteration % 5 == 0 and not is_in_middle_of_tools:
        state = self._memory.get_current_state()
        reflection = self._build_reflection_prompt(state)
        self._memory.append({
          "role": "system",
          "content": reflection,
          "_importance": "ANCHOR"
        })

      self._iteration += 1
      tok = self._memory.token_estimate()
      sys_logger.info(f"===== 第 {self._iteration} 轮迭代开始，当前内存消息数: {len(self._memory.messages)}，预估 Token: {tok} =====")

      messages_to_send = self._memory.prepare_for_llm(keep_last_n=3)

      response = self._llm.chat(
          messages=messages_to_send,
          system_prompt=self._get_effective_system_prompt(),
          tools=self._build_tool_specs(),
          max_tokens=self._manifest.max_tokens,
      )

      if response.finish_reason == "error":
        print(f"[CVA] ❌ LLM 错误: {response.text}")
        consecutive_failures += 1
        if consecutive_failures >= MAX_RETRIES:
          print(f"[CVA] ❌ 连续 {MAX_RETRIES} 次失败，停止运行")
          break
        continue

      consecutive_failures = 0

      if response.text and response.text.strip():
        print(f"\n🤖 {response.text}")

      self._memory.append(
          convert_assistant_with_tools_to_litellm(response.text, response.tool_calls)
      )

      if response.finish_reason == "stop":
        print("\n[CVA] ✅ 任务完成")
        cont = self._safe_input("\n[CVA] 继续对话？（直接回车退出）: ")
        if cont:
          self._memory.append({"role": "user", "content": cont})
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

  _P0_TOOLS = {"run_shell"}
  _P1_TOOLS = {"write_file", "append_file", "backup_file"}

  def _dispatch_tool(self, tool_name: str, tool_input: Dict, call_id: str) -> Dict:
    print(f"\n🔧 {tool_name}({json.dumps(tool_input, ensure_ascii=False)[:120]})")
    enriched_input = {**tool_input, "_context_summary": self._context_summary()}

    if tool_name in self._P0_TOOLS:
      review = self._pre_execute_review(tool_name, tool_input)
      if not review.get("is_safe", True):
        issues = "; ".join(review.get("issues", ["未知问题"]))
        suggestion = review.get("suggestion", "请检查后重试")
        print(f"   🛑 [自省拦截] 发现问题：{issues}")
        print(f"   💡 建议：{suggestion}")
        result = {
          "status": "error",
          "message": f"[自省拦截] 操作被安全检查阻止。问题：{issues}。建议：{suggestion}"
        }
        return convert_tool_result_to_litellm(call_id, json.dumps(result, ensure_ascii=False))

    tool = self._tools.get(tool_name)
    if not tool:
      result = {"status": "error", "message": f"工具 `{tool_name}` 未注册"}
    else:
      try:
        result = tool.execute(**enriched_input)
        if tool_name == "submit_plan" and result.get("status") == "ok":
          self._memory.update_task_state(
              goal=tool_input.get("goal", ""),
              milestones=tool_input.get("milestones", []),
              iteration=self._iteration,
          )
          self._memory.get_current_state().add_knowledge(
              "last_plan_iteration", str(self._iteration)
          )
      except Exception as e:
        result = {"status": "error", "message": str(e)}

    icon = "✅" if result.get("status") == "ok" else "❌"
    print(f"   {icon} {json.dumps(result, ensure_ascii=False)[:200]}")
    return convert_tool_result_to_litellm(call_id, json.dumps(result, ensure_ascii=False))

  def _build_tool_specs(self) -> List[Dict]:
    return [t.to_api_spec() for t in self._tools.values()]

  # ── 辅助方法 ──

  def _safe_input(self, _prompt: str):
    sys.stdout.write(_prompt)
    sys.stdout.flush()
    if hasattr(sys.stdin, 'buffer'):
      line = sys.stdin.buffer.readline()
      try:
        return line.decode('utf-8').strip()
      except UnicodeDecodeError:
        return line.decode('gbk', errors='replace').strip()
    else:
      return sys.stdin.readline().strip()

  def _visual_len(self, text: str) -> int:
    length = 0
    for char in text:
      if unicodedata.east_asian_width(char) in ('W', 'F'):
        length += 2
      else:
        length += 1
    return length

  def _pad_line(self, label: str, value: str, width: int = 50) -> str:
    return f"  {label:<10} : {value}"

  def _print_banner(self):
    m = self._manifest
    sid = self._memory.session_id
    status = "恢复 (Resumed)" if self._memory.messages else "新建 (New)"
    line = "─" * 110
    print(f"\n{line}")
    print(f" 🚀 CVA SYSTEM v3.6 | {m.role_name}")
    print(f"{line}")
    print(self._pad_line("模型", self._model))
    print(self._pad_line("Session", sid))
    print(self._pad_line("状态", status))
    print(f"{line}\n")

  def _get_effective_system_prompt(self) -> str:
    llm_stats = self._llm.stats
    mem_stats = self._memory.stats

    cost_report = textwrap.dedent(f"""
      ---
      ### 💰 资源消耗报告 (Resource Usage)
      - 本次会话累计调用: {llm_stats.total_calls} 次
      - 累计消耗 Token: {llm_stats.total_tokens:,}
      - 内存上下文长度: {mem_stats.memory_messages} 条消息 (预估 {mem_stats.token_estimate} tokens)
      - 提示：请评估任务复杂度与 Token 消耗。如果消耗过快且无进展，请反思并切换更高效的策略。
    """).strip()

    raw_prompt = self._manifest.identity_prompt
    cap_json = json.dumps(self._manifest.capabilities, ensure_ascii=False, indent=2)
    cap_json = f"```json\n{cap_json}\n```"
    perm_json = json.dumps(self._perm.snapshot(), ensure_ascii=False, indent=2)
    perm_json = f"```json\n{perm_json}\n```"

    effective_prompt = raw_prompt.replace("${capabilities}", cap_json)
    effective_prompt = effective_prompt.replace("${permissions}", perm_json)

    law_prompt = textwrap.dedent(f"""
      ---
      ### ⚡ 运行时状态 (实时更新)
      - 当前会话 ID: {self._memory.session_id}
      - 迭代次数: {self._iteration}/{self._max_iterations}
      - 提示：底座会自动对旧消息历史进行脱水，如需查看完整代码请重新 read_file。
    """).strip()

    gui_hint = ""
    if "computer_control" in self._manifest.capabilities:
      gui_hint = textwrap.dedent("""
            ### 🖥️ GUI 操作指南
            - 屏幕截图已缩放至 1024x1024 归一化坐标系。
            - 使用 computer_control 时，请确保坐标在屏幕范围内。
            - 在点击前，建议先调用 take_screenshot 确认目标位置。
        """).strip()

    task_state_block = self._memory.get_current_state().to_prompt_block()
    parts = [effective_prompt, cost_report, law_prompt, gui_hint]
    if task_state_block:
      parts.append(task_state_block)

    return "\n\n".join(parts)

  def _build_reflection_prompt(self, state) -> str:
    if not state.current_goal:
      return "**自主反思**：你已执行多轮操作。请评估当前进度，如有需要请调用 submit_plan 更新计划。"

    completed = len(state.completed_steps)
    total = len(state.plan)
    active = state.active_step or "（无明确步骤）"

    prompt_parts = [
      f"**自主反思**（第 {self._iteration} 轮）：",
      f"- 当前目标：{state.current_goal}",
      f"- 进度：{completed}/{total} 步骤完成，当前步骤：{active}",
    ]

    if state.pending_risks:
      prompt_parts.append(f"- ⚠️ 待处理风险：{'; '.join(state.pending_risks[-2:])}")

    if completed == 0 and self._iteration > 10:
      prompt_parts.append("- 🔴 警告：已执行 10+ 轮但无步骤完成，请评估是否需要重新规划。")
    elif completed == total and total > 0:
      prompt_parts.append("- ✅ 所有步骤已完成，请总结结果并宣布任务完成。")
    else:
      prompt_parts.append("- 请确认当前步骤是否在正确路径上，如有偏差请调用 submit_plan 更新。")

    return "\n".join(prompt_parts)

  def _pre_execute_review(self, tool_name: str, tool_input: Dict) -> Dict:
    state = self._memory.get_current_state()
    state_summary = f"当前步骤：{state.active_step}" if state.active_step else "无明确任务步骤"

    user_msg = textwrap.dedent(f"""
      即将执行高危工具，请评估安全性：

      工具名称：{tool_name}
      工具参数：{json.dumps(tool_input, ensure_ascii=False, indent=2)[:800]}
      {state_summary}

      请重点检查：
      1. 路径是否正确（有无拼写错误、路径穿越风险）
      2. 操作是否可逆（写操作前是否应先备份）
      3. 命令是否包含危险参数（如 rm -rf、chmod 777 等）
      4. 内容是否与当前任务目标相符
    """).strip()

    output_schema = {
      "type": "object",
      "properties": {
        "is_safe": {"type": "boolean", "description": "操作是否安全可以执行"},
        "issues": {"type": "array", "items": {"type": "string"}, "description": "发现的问题列表"},
        "suggestion": {"type": "string", "description": "修改建议（is_safe=false 时必填）"},
      },
      "required": ["is_safe", "issues", "suggestion"],
    }

    result = self._llm.structured_chat(
        messages=[{"role": "user", "content": user_msg}],
        system_prompt="你是 CVA 代码安全审查模块。仅判断操作的技术安全性，不考虑业务逻辑。用简洁的中文回答。",
        output_schema=output_schema,
        function_name="submit_review",
        function_description="提交安全审查结果",
        max_tokens=512,
    )

    if result is None:
      print("   ⚠️  [自省] LLM 调用失败，跳过安全检查")
      return {"is_safe": True, "issues": [], "suggestion": ""}

    return result

  def _should_dehydrate(self, content: str) -> bool:
    return ("artifact_type" in content and
            '"file_content"' in content and
            len(content) > 1000)

  def _extract_python_outline(self, code: str) -> str:
    outline = []
    lines = code.split('\n')
    for line in lines:
      stripped = line.strip()
      if stripped.startswith(('def ', 'class ')):
        outline.append(line)
    return "\n".join(outline[:40])

  def _cleanup_dehydration_cache(self):
    current_time = time.time()
    expired_keys = [
      k for k, v in self._dehydration_cache.items()
      if current_time - v["timestamp"] > self._DEHYDRATION_CACHE_TTL
    ]
    for key in expired_keys:
      del self._dehydration_cache[key]

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
      return PreScreenResult(is_necessary=True, reasoning="调用失败。")
    return PreScreenResult(
        is_necessary=bool(result.get("is_necessary")),
        reasoning=str(result.get("reasoning")),
        alternative=str(result.get("alternative"))
    )

  def _context_summary(self, last_n: int = 6) -> str:
    msgs = self._memory.messages
    recent = msgs[-last_n:] if len(msgs) > last_n else msgs
    lines = []
    for m in recent:
      role = m.get("role", "")
      if role == "user":
        text = str(m.get("content", ""))
        if text:
          lines.append(f"[用户] {text[:150]}")
      elif role == "assistant":
        text = str(m.get("content", ""))
        tool_calls = m.get("tool_calls", [])
        if text:
          lines.append(f"[助手] {text[:150]}")
        for tc in tool_calls:
          if isinstance(tc, dict):
            fn = tc.get("function", {})
            lines.append(f"[调用] {fn.get('name', '?')}({str(fn.get('arguments', ''))[:80]})")
      elif role == "tool":
        try:
          data = json.loads(m.get("content", "{}"))
          status = data.get("status", "?")
          inner = data.get("data", data.get("message", ""))
          summary = str(inner)[:120] if inner else ""
          lines.append(f"[工具结果:{status}] {summary}")
        except Exception:
          lines.append(f"[工具结果] {str(m.get('content', ''))[:100]}")
    return "\n".join(lines)


def _hash(text: str) -> str:
  import hashlib
  return hashlib.sha256(text.encode()).hexdigest()[:16]
