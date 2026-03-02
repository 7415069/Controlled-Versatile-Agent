"""
统一底座（Universal Shell）v3.3 — 补全缺失方法与视觉对齐
"""

import json
import sys
import textwrap
import time
import unicodedata
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
      "resumed": len(self._memory.messages) > 0,
    })

    print("\n[CVA] 请输入任务（直接回车继续上次对话）：")
    user_task = self._safe_input("> ")

    if user_task:
      self._memory.append({"role": "user", "content": user_task})
    elif not self._memory.messages:
      self._memory.append({"role": "user", "content": "请先探索当前工作目录。"})

    self._run_loop()

  def stop(self, reason: str = "normal"):
    duration = round(time.time() - (self._start_time or time.time()), 2)
    self._memory.close()
    print(f"\n[CVA] Agent 已停止（{reason}，耗时 {duration}s）")

  # ── 主循环 ─────────────────────────────────────────────────

  def _run_loop(self):
    while self._iteration < self._max_iterations:
      self._iteration += 1
      tok = self._memory.token_estimate()
      print(f"\n[CVA] ── 第 {self._iteration} 轮推理（≈{tok:,} tokens）──")

      messages_to_send = self._prepare_dehydrated_messages(keep_last_n=4)

      # 调用 LLM
      response = self._llm.chat(
          messages=messages_to_send,
          system_prompt=self._get_effective_system_prompt(),
          tools=self._build_tool_specs(),  # 确保此方法存在
          max_tokens=self._manifest.max_tokens,
      )

      if response.finish_reason == "error":
        print(f"[CVA] ❌ LLM 错误: {response.text}")
        break

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

  def _dispatch_tool(self, tool_name: str, tool_input: Dict, call_id: str) -> Dict:
    t0 = time.time()
    print(f"\n🔧 {tool_name}({json.dumps(tool_input, ensure_ascii=False)[:120]})")
    enriched_input = {**tool_input, "_context_summary": self._context_summary()}
    tool = self._tools.get(tool_name)
    if not tool:
      result = {"status": "error", "message": f"工具 `{tool_name}` 未注册"}
    else:
      try:
        result = tool.execute(**enriched_input)
      except Exception as e:
        result = {"status": "error", "message": str(e)}

    icon = "✅" if result.get("status") == "ok" else "❌"
    print(f"   {icon} {json.dumps(result, ensure_ascii=False)[:200]}")
    return convert_tool_result_to_litellm(call_id, json.dumps(result, ensure_ascii=False))

  def _build_tool_specs(self) -> List[Dict]:
    """补全缺失的方法：将注册的工具转换为 API 定义格式"""
    return [t.to_api_spec() for t in self._tools.values()]

  # ── 辅助方法 ──

  def _safe_input(self, prompt: str) -> str:
    try:
      return input(prompt).strip()
    except UnicodeDecodeError:
      print("\n[系统] 输入包含非标准字符，尝试自动修复...")
      raw_data = sys.stdin.buffer.readline()
      return raw_data.decode(sys.stdin.encoding or 'utf-8', errors='replace').strip()
    except EOFError:
      return ""

  def _visual_len(self, text: str) -> int:
    """计算字符串的视觉宽度"""
    length = 0
    for char in text:
      if unicodedata.east_asian_width(char) in ('W', 'F'):
        length += 2
      else:
        length += 1
    return length

  def _pad_line(self, label: str, value: str, width: int = 56) -> str:
    """对一行内容进行视觉宽度对齐"""
    line_content = f"  {label:<10}: {value}"
    vlen = self._visual_len(line_content)
    padding = " " * max(0, width - vlen)
    return f"║ {line_content}{padding} ║"

  def _print_banner(self):
    m = self._manifest
    sid = self._memory.session_id
    status = "恢复 (Resumed)" if self._memory.messages else "新建 (New)"

    inner_width = 58
    line = "═" * inner_width

    print("\n╔" + line + "╗")
    title = " 受控百变智能体 (CVA) v2  —  启动中 "
    v_title_len = self._visual_len(title)
    title_padding = " " * ((inner_width - v_title_len) // 2)
    # 处理奇数宽度差
    suffix_padding = title_padding + (" " if (inner_width - v_title_len) % 2 != 0 else "")
    print(f"║{title_padding}{title}{suffix_padding}║")
    print("╠" + line + "╣")
    print(self._pad_line("角色", m.role_name))
    print(self._pad_line("模型", self._model))
    print(self._pad_line("Session", sid[:36]))
    print(self._pad_line("记忆状态", status))
    print("╚" + line + "╝")

  def _get_effective_system_prompt(self) -> str:
    base_prompt = self._manifest.identity_prompt
    current_perms = self._perm.snapshot()
    law_prompt = textwrap.dedent(f"""
      ### ⚠️ 运行环境与权限准则 (必读) ⚠️
      1. 读: {current_perms['read']} | 写: {current_perms['write']} | 命令: {current_perms['shell']}
      2. 💡 提示：底座会自动对旧消息历史进行“脱水”处理以节省 Token。
      """).strip()
    return f"{base_prompt}\n\n{law_prompt}"

  def _prepare_dehydrated_messages(self, keep_last_n: int = 4) -> List[Dict]:
    raw_msgs = self._memory.messages
    dehydrated_msgs = []
    threshold_idx = len(raw_msgs) - keep_last_n
    for i, msg in enumerate(raw_msgs):
      new_msg = msg.copy()
      if i < threshold_idx and msg.get("role") == "user":
        content_str = msg.get("content", "")
        if "artifact_type" in content_str and '"file_content"' in content_str:
          try:
            json_part = content_str.split("\n", 1)[1] if content_str.startswith("[TOOL_RESULT") else content_str
            data = json.loads(json_part)
            if data.get("artifact_type") == "file_content" and len(data.get("content", "")) > 1500:
              outline = self._extract_python_outline(data["content"])
              data["metadata"]["is_full_text"] = False
              data["content"] = f"[DEHYDRATED] 代码大纲：\n{outline}\n(如需修改，请重读全文)"
              prefix = "[TOOL_RESULT (Dehydrated)]\n" if content_str.startswith("[TOOL_RESULT") else ""
              new_msg["content"] = prefix + json.dumps(data, ensure_ascii=False)
          except:
            pass
      dehydrated_msgs.append(new_msg)
    return dehydrated_msgs

  def _extract_python_outline(self, code: str) -> str:
    outline = []
    lines = code.split('\n')
    for line in lines:
      stripped = line.strip()
      if stripped.startswith(('def ', 'class ')):
        outline.append(line)
    return "\n".join(outline[:40])

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
