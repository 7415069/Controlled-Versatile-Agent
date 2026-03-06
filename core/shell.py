"""
统一底座（Universal Shell）v3.5 - Token优化版
优化内容：
- 消息脱水性能优化：缓存解析结果，减少重复计算
- Token估算优化：增加缓存时间，减少计算频率
- 工具执行失败处理：改进错误处理逻辑
- 脱水缓存时间延长：10秒 -> 60秒
- 保留消息数减少：4条 -> 3条
- 脱水触发阈值降低：2000字符 -> 1000字符
- System Prompt简化：减少权限列表冗余
"""

import json
import sys
import textwrap
import threading
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
from core.logger import sys_logger
from core.manifest import load_manifest, RoleManifest
from core.memory import MemoryStore
from core.permissions import PermissionChecker
from core.tool import build_tools


class UniversalShell:
  """
  CVA 唯一的业务无关运行时 v3.4。
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
      use_gui: bool = True,
  ):
    self._instance_id = str(uuid.uuid4())
    self._model = model
    self._max_iterations = max_iterations
    self._iteration = 0
    self._start_time = None
    self._use_gui = use_gui

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
        model=model,
    )

    self._cleanup_thread: Optional[threading.Thread] = None
    # 性能优化：缓存脱水结果
    self._dehydration_cache: Dict[int, Dict] = {}
    self._last_dehydration_time = 0.0
    self._DEHYDRATION_CACHE_TTL = 60.0  # 缓存60秒，减少重复计算

  # ── 生命周期 ───────────────────────────────────────────────

  def start(self):
    self._start_time = time.time()
    self._print_banner()

    self._logger.log("AGENT_START", {
      "model": self._model,
      "session_id": self._memory.session_id,
      "resumed": len(self._memory.messages) > 0,
    })

    self._cleanup_thread = threading.Thread(
        target=self._periodic_cleanup, daemon=True, name="CVA-Permission-Cleanup"
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
    """每 5 分钟自动清理过期权限（改进点3）"""
    while True:
      time.sleep(300)
      try:
        self._escalation.cleanup_expired_permissions()
      except Exception as e:
        print(f"[CVA] ⚠️ 自动清理线程异常: {e}")

  def stop(self, reason: str = "normal"):
    duration = round(time.time() - (self._start_time or time.time()), 2)
    self._memory.close()
    print(f"\n[CVA] Agent 已停止（{reason}，耗时 {duration}s）")

  # ── 主循环 ─────────────────────────────────────────────────

  def _run_loop(self):
    consecutive_failures = 0
    MAX_CONSECUTIVE_FAILURES = 3

    sys_logger.info(f"开始任务循环。Session ID: {self._memory.session_id}")
    while self._iteration < self._max_iterations:
      # 只有当上一条消息不是 tool_calls 时，才插入系统指令
      last_msg = self._memory.messages[-1] if self._memory.messages else {}
      is_in_middle_of_tools = last_msg.get("role") == "assistant" and "tool_calls" in last_msg

      if self._iteration > 0 and self._iteration % 5 == 0 and not is_in_middle_of_tools:
        self._memory.append({
          "role": "system",
          "content": "**自主反思指令**：你已执行多轮操作。请评估当前进度，是否需要修正计划？"
        })

      self._iteration += 1
      tok = self._memory.token_estimate()
      # print(f"\n[CVA] ── 第 {self._iteration} 轮推理（≈{tok:,} tokens）──")
      sys_logger.info(f"===== 第 {self._iteration} 轮迭代开始，当前内存消息数: {len(self._memory.messages)}，预估 Token: {tok} =====")

      # messages_to_send = self._prepare_dehydrated_messages(keep_last_n=3)
      messages_to_send = self._memory.prepare_for_llm(keep_last_n=3)

      # 调用 LLM
      response = self._llm.chat(
          messages=messages_to_send,
          system_prompt=self._get_effective_system_prompt(),
          tools=self._build_tool_specs(),
          max_tokens=self._manifest.max_tokens,
      )

      if response.finish_reason == "error":
        print(f"[CVA] ❌ LLM 错误: {response.text}")
        consecutive_failures += 1
        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
          print(f"[CVA] ❌ 连续 {MAX_CONSECUTIVE_FAILURES} 次失败，停止运行")
          break
        continue

      # 重置失败计数器
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
    sys.stdout.write(prompt)
    sys.stdout.flush()

    # 智能判断是文本流还是字节流
    if hasattr(sys.stdin, 'buffer') and hasattr(sys.stdin.buffer, 'readline'):
      # 如果有 buffer 属性且可读，认为是字节流
      line = sys.stdin.buffer.readline()
      try:
        return line.decode('utf-8').strip()
      except UnicodeDecodeError:
        return line.decode('gbk', errors='replace').strip()
    else:
      # 否则直接从文本流读取字符串
      return sys.stdin.readline().strip()

  # def _safe_input(self, prompt: str) -> str:
  #   try:
  #     return input(prompt).strip()
  #   except UnicodeDecodeError:
  #     print("\n[系统] 输入包含非标准字符，尝试自动修复...")
  #     raw_data = sys.stdin.buffer.readline()
  #     return raw_data.decode(sys.stdin.encoding or 'utf-8', errors='replace').strip()
  #   except EOFError:
  #     return ""

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
    title = " 受控百变智能体 (CVA) v3.4  —  启动中 "
    v_title_len = self._visual_len(title)
    title_padding = " " * ((inner_width - v_title_len) // 2)
    suffix_padding = title_padding + (" " if (inner_width - v_title_len) % 2 != 0 else "")
    print(f"║{title_padding}{title}{suffix_padding}║")
    print("╠" + line + "╣")
    print(self._pad_line("角色", m.role_name))
    print(self._pad_line("模型", self._model))
    print(self._pad_line("Session", sid[:36]))
    print(self._pad_line("记忆状态", status))
    print("╚" + line + "╝")

  def _get_effective_system_prompt(self) -> str:

    llm_stats = self._llm.stats
    mem_stats = self._memory.stats

    cost_report = textwrap.dedent(f"""
      ---
      ### 💰 资源消耗报告 (Resource Usage)
      - 本次会话累计调用: {llm_stats.total_calls} 次
      - 累计消耗 Token: {llm_stats.total_tokens:,}
      - 内存上下文长度: {mem_stats.memory_messages} 条消息 (预估 {mem_stats.token_estimate} tokens)
      - 提示：请评估任务复杂度与 Token 消耗。如果消耗过快且无进展，请反思并切换更高效的策略（如编写批量处理脚本）。
    """).strip()

    # 1. 获取 YAML 中定义的原始 identity_prompt
    raw_prompt = self._manifest.identity_prompt
    # 2. 获取能力和权限列表
    cap_json = json.dumps(self._manifest.capabilities, ensure_ascii=False, indent=2)
    cap_json = f"```json\n{cap_json}\n```"

    perm_json = json.dumps(self._perm.snapshot(), ensure_ascii=False, indent=2)
    perm_json = f"```json\n{perm_json}\n```"

    # 3. 执行变量替换
    # 这样 YAML 里的 ${capabilities} 和 ${init_permissions} 就会变成真实数据
    effective_prompt = raw_prompt.replace("${capabilities}", cap_json)
    effective_prompt = effective_prompt.replace("${permissions}", perm_json)

    # 4. 额外补充当前的运行时环境（可选，但极有用）
    law_prompt = textwrap.dedent(f"""
      ---
      ### ⚡ 运行时状态 (实时更新)
      - 当前会话 ID: {self._memory.session_id}
      - 迭代次数: {self._iteration}/{self._max_iterations}
      - 提示：底座会自动对旧消息历史进行脱水，如需查看完整代码请重新 read_file。
    """).strip()

    return f"{effective_prompt}\n\n{cost_report}\n\n{law_prompt}"

  def _should_dehydrate(self, content: str) -> bool:
    """快速判断是否需要脱水"""
    return ("artifact_type" in content and
            '"file_content"' in content and
            len(content) > 1000)

  def _extract_python_outline(self, code: str) -> str:
    """提取Python代码大纲"""
    outline = []
    lines = code.split('\n')
    for line in lines:
      stripped = line.strip()
      if stripped.startswith(('def ', 'class ')):
        outline.append(line)
    return "\n".join(outline[:40])

  def _cleanup_dehydration_cache(self):
    """清理过期的脱水缓存"""
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
    return PreScreenResult(is_necessary=bool(result.get("is_necessary")), reasoning=str(result.get("reasoning")), alternative=str(result.get("alternative")))

  def _context_summary(self, last_n: int = 6) -> str:
    """生成上下文摘要"""
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
