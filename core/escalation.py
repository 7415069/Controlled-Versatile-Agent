"""
权限申请管理器（Escalation Manager）v2
流程：越权拦截 → LLM 自我二次确认 → 必须则人类审批 → 即时赋能

新增机制：
  在推给人类审批之前，先让 LLM 自我评估：
    "这个越权操作是完成任务的必要条件吗？还是有其他替代方案？"
  - LLM 认为"不必须" → 直接降级拒绝，返回建议的替代路径，不打扰人类
  - LLM 认为"必须"   → 走 GUI / 控制台审批流程
"""

import fnmatch
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional

from core.manifest import EscalationPolicy
from core.permissions import PermissionChecker


class EscalationStatus(Enum):
  PENDING = "PENDING"
  APPROVED = "APPROVED"
  DENIED = "DENIED"
  AUTO_DENIED = "AUTO_DENIED"
  LLM_SELF_DENIED = "LLM_SELF_DENIED"  # LLM 自我评估后主动放弃
  TIMEOUT = "TIMEOUT"


@dataclass
class EscalationRequest:
  request_id: str
  tool_name: str
  requested_path: str
  permission_type: str
  reason: str
  context_summary: str
  timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
  status: EscalationStatus = EscalationStatus.PENDING
  decision_time: Optional[str] = None
  approved_paths: List[str] = field(default_factory=list)
  deny_reason: Optional[str] = None
  llm_pre_screen_result: Optional[str] = None  # "necessary" | "unnecessary"
  llm_pre_screen_reason: Optional[str] = None


@dataclass
class PreScreenResult:
  """LLM 二次确认的结构化结果"""
  is_necessary: bool
  reasoning: str
  alternative: str = ""


class EscalationManager:
  def __init__(
      self,
      policy: EscalationPolicy,
      permission_checker: PermissionChecker,
      audit_log_fn: Callable,
      llm_call_fn: Optional[Callable] = None,
      # llm_call_fn 新签名: (EscalationRequest) -> PreScreenResult
      # 由 shell.py 注入，escalation.py 自身不依赖任何 LLM 库
  ):
    self._policy = policy
    self._perm = permission_checker
    self._audit = audit_log_fn
    self._llm_call = llm_call_fn
    self._pending: Dict[str, EscalationRequest] = {}
    self._lock = threading.Lock()

  def set_llm_call_fn(self, fn: Callable):
    """Shell 初始化完成后注入 LLM 调用函数，避免循环依赖"""
    self._llm_call = fn

  # ─── 核心检查入口 ──────────────────────────────────────────

  def check(
      self,
      tool_name: str,
      target: str,
      permission_type: str,
      reason: str = "",
      context_summary: str = "",
  ) -> tuple[bool, Optional[str]]:

    # 1. 命中自动拒绝黑名单
    if self._matches_auto_deny(target):
      self._audit("AUTO_DENIED", {
        "tool_name": tool_name,
        "target": target,
        "matched_pattern": self._find_auto_deny_pattern(target),
      })
      return False, (
        f"访问被自动拒绝：路径 `{target}` 命中安全黑名单。\n"
        "如需访问，请联系管理员修改 Manifest auto_deny_patterns 配置。"
      )

    # 2. 白名单内 → 放行
    if self._is_permitted(tool_name, target, permission_type):
      return True, None

    # 3. 越权 → 创建请求记录
    req = self._create_request(tool_name, target, permission_type, reason, context_summary)

    # 4. LLM 自我二次确认
    pre_screen = self._llm_pre_screen(req)
    req.llm_pre_screen_result = "necessary" if pre_screen.is_necessary else "unnecessary"
    req.llm_pre_screen_reason = pre_screen.reasoning

    if not pre_screen.is_necessary:
      # 降级拒绝，不打扰人类
      req.status = EscalationStatus.LLM_SELF_DENIED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      req.deny_reason = f"LLM 自我评估：不必须。{pre_screen.reasoning}"

      self._audit("LLM_SELF_DENIED", {
        "request_id": req.request_id,
        "tool_name": tool_name,
        "target": target,
        "llm_reasoning": pre_screen.reasoning,
        "alternative": pre_screen.alternative,
      })

      deny_msg = (
        f"越权访问 `{target}` 已被智能降级拒绝（无需人类介入）。\n"
        f"LLM 判断：{pre_screen.reasoning}\n"
      )
      if pre_screen.alternative:
        deny_msg += f"建议替代方案：{pre_screen.alternative}"
      return False, deny_msg

    # 5. LLM 确认必须 → 人类审批
    self._audit("LLM_PRE_SCREEN_PASSED", {
      "request_id": req.request_id,
      "llm_reasoning": pre_screen.reasoning,
    })
    approved, message = self._ask_human(req)
    return (True, None) if approved else (False, message)

  # ─── 人类决策接口 ──────────────────────────────────────────

  def approve(self, request_id: str, approved_paths: Optional[List[str]] = None):
    with self._lock:
      req = self._pending.get(request_id)
      if not req:
        return
      req.status = EscalationStatus.APPROVED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      paths = approved_paths if approved_paths else [req.requested_path]
      req.approved_paths = paths

      if req.permission_type in ("read", "list"):
        self._perm.grant_read(paths)
      elif req.permission_type == "write":
        self._perm.grant_write(paths)
        self._perm.grant_read(paths)
      elif req.permission_type == "shell":
        self._perm.grant_shell(paths)

      self._audit("ESCALATION_APPROVED", {
        "request_id": request_id,
        "approved_paths": paths,
        "approver": "human_supervisor",
        "new_whitelist": self._perm.snapshot(),
      })

  def deny(self, request_id: str, reason: str = ""):
    with self._lock:
      req = self._pending.get(request_id)
      if not req:
        return
      req.status = EscalationStatus.DENIED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      req.deny_reason = reason
      self._audit("ESCALATION_DENIED", {
        "request_id": request_id,
        "deny_reason": reason,
      })

  # ─── LLM 自我二次确认（结构化输出版）────────────────────

  def _llm_pre_screen(self, req: EscalationRequest) -> PreScreenResult:
    """
    通过 structured_chat（function calling）强制获取结构化判断结果。
    llm_call_fn 签名已升级为: (EscalationRequest) -> PreScreenResult
    escalation.py 自身不再依赖 json / re，零解析风险。
    """
    if not self._llm_call:
      return PreScreenResult(
          is_necessary=True,
          reasoning="LLM 二次确认不可用（未注入），保守升级到人类审批。",
      )

    print(f"\n[CVA·二次确认] 🤔 正在评估越权必要性: {req.tool_name}({req.requested_path})")
    try:
      result = self._llm_call(req)  # shell.py 负责所有 LLM 交互细节
      if not isinstance(result, PreScreenResult):
        raise TypeError(f"期望 PreScreenResult，收到 {type(result)}")
      label = "✅ 必须，升级人类审批" if result.is_necessary else "🚫 不必须，智能降级拒绝"
      print(f"[CVA·二次确认] {label}")
      print(f"[CVA·二次确认] 理由: {result.reasoning}")
      if result.alternative:
        print(f"[CVA·二次确认] 替代方案: {result.alternative}")
      return result
    except Exception as e:
      print(f"[CVA·二次确认] ⚠️  调用异常（{e}），保守升级到人类审批。")
      return PreScreenResult(
          is_necessary=True,
          reasoning=f"二次确认异常，保守处理：{e}",
      )

  # ─── 人类审批（GUI 优先，控制台降级）────────────────────

  def _ask_human(self, req: EscalationRequest) -> tuple[bool, str]:
    print("\n" + "═" * 60)
    print("🔐 [CVA 权限申请] — LLM 已确认此操作必须，请您裁定")
    print("═" * 60)
    print(f"  申请 ID   : {req.request_id}")
    print(f"  工具      : {req.tool_name}")
    print(f"  申请路径  : {req.requested_path}")
    print(f"  权限类型  : {req.permission_type}")
    print(f"  申请理由  : {req.reason or '（未提供）'}")
    print(f"  LLM 评估  : {req.llm_pre_screen_reason or '已通过必要性确认'}")
    print("─" * 60)

    gui_result = self._try_gui_approval(req)
    if gui_result is not None:
      return gui_result
    return self._console_approval(req)

  def _try_gui_approval(self, req: EscalationRequest) -> Optional[tuple[bool, str]]:
    try:
      import tkinter as tk
      from tkinter import messagebox, simpledialog

      # 测试 display 是否可用
      root = tk.Tk()
      root.withdraw()
      root.update()

      info_text = (
        f"工具: {req.tool_name}\n"
        f"类型: {req.permission_type.upper()}\n"
        f"路径: {req.requested_path}\n\n"
        f"申请理由:\n{req.reason or '未说明'}\n\n"
        f"LLM 评估:\n{req.llm_pre_screen_reason or '已通过必要性确认'}"
      )

      choice = messagebox.askyesnocancel(
          title="🔐 CVA 权限申请（LLM 已确认必须）",
          message=info_text,
          detail="[是] 批准  [否] 拒绝  [取消] 修改路径后批准",
          icon="warning",
      )

      if choice is True:
        root.destroy()
        self.approve(req.request_id)
        print("  ✅ [GUI] 已批准")
        print("═" * 60 + "\n")
        return True, ""

      elif choice is False:
        deny_reason = simpledialog.askstring(
            "拒绝理由", "请输入拒绝原因（可选）:", parent=root
        )
        root.destroy()
        self.deny(req.request_id, deny_reason or "人类直接拒绝")
        print(f"  ❌ [GUI] 已拒绝。原因: {deny_reason or '无'}")
        print("═" * 60 + "\n")
        return False, f"访问被人类导师拒绝：{deny_reason or ''}"

      elif choice is None:
        new_path = simpledialog.askstring(
            "修改路径",
            f"原申请: {req.requested_path}\n请输入批准的路径（多个用逗号分隔）:",
            initialvalue=req.requested_path,
            parent=root,
        )
        root.destroy()
        if new_path and new_path.strip():
          paths = [p.strip() for p in new_path.split(",") if p.strip()]
          self.approve(req.request_id, paths)
          print(f"  ✅ [GUI] 已批准修改后路径: {paths}")
          print("═" * 60 + "\n")
          return True, ""
        else:
          self.deny(req.request_id, "修改路径为空")
          print("  ❌ [GUI] 路径为空，已拒绝")
          print("═" * 60 + "\n")
          return False, "修改路径为空，视为拒绝"

    except Exception as e:
      print(f"  [系统] GUI 不可用（{e}），切换控制台审批...")
      return None

  def _console_approval(self, req: EscalationRequest) -> tuple[bool, str]:
    print("  选项: [y] 批准  [n] 拒绝  [m] 修改路径后批准")
    print("─" * 60)

    timeout = self._policy.timeout_seconds
    choice = self._input_with_timeout(
        f"  请输入选项（{timeout}s 超时自动拒绝）: ", timeout
    )

    if choice is None:
      req.status = EscalationStatus.TIMEOUT
      req.decision_time = datetime.now(timezone.utc).isoformat()
      self._audit("ESCALATION_DENIED", {
        "request_id": req.request_id,
        "deny_reason": "timeout",
      })
      print("  ⏱️  超时，自动拒绝。")
      print("═" * 60 + "\n")
      return False, f"权限申请超时（{timeout}s），访问 `{req.requested_path}` 被拒绝。"

    choice = choice.strip().lower()

    if choice == "y":
      self.approve(req.request_id)
      print("  ✅ [控制台] 已批准，白名单已更新。")
      print("═" * 60 + "\n")
      return True, ""

    elif choice == "m":
      new_path = input("  请输入批准的路径（多个逗号分隔）: ").strip()
      if new_path:
        paths = [p.strip() for p in new_path.split(",") if p.strip()]
        self.approve(req.request_id, paths)
        print(f"  ✅ [控制台] 已批准: {paths}")
        print("═" * 60 + "\n")
        return True, ""
      else:
        self.deny(req.request_id, "修改路径为空")
        print("  ❌ 路径为空，已拒绝。")
        print("═" * 60 + "\n")
        return False, "修改路径为空，视为拒绝"

    else:
      deny_reason = input("  拒绝原因（可选，回车跳过）: ").strip()
      self.deny(req.request_id, deny_reason)
      print("  ❌ [控制台] 已拒绝。")
      print("═" * 60 + "\n")
      suffix = f"，原因：{deny_reason}" if deny_reason else ""
      return False, f"访问 `{req.requested_path}` 被人类导师拒绝{suffix}。"

  # ─── 工具方法 ──────────────────────────────────────────────

  @staticmethod
  def _input_with_timeout(prompt: str, timeout: int) -> Optional[str]:
    if sys.platform == "win32":
      try:
        return input(prompt)
      except EOFError:
        return None
    import signal
    def _handler(signum, frame):
      raise TimeoutError()

    try:
      signal.signal(signal.SIGALRM, _handler)
      signal.alarm(timeout)
      result = input(prompt)
      signal.alarm(0)
      return result
    except (TimeoutError, EOFError):
      signal.alarm(0)
      return None

  def _matches_auto_deny(self, target: str) -> bool:
    return any(
        fnmatch.fnmatch(target, p) or target.startswith(p.rstrip("*"))
        for p in self._policy.auto_deny_patterns
    )

  def _find_auto_deny_pattern(self, target: str) -> str:
    for p in self._policy.auto_deny_patterns:
      if fnmatch.fnmatch(target, p) or target.startswith(p.rstrip("*")):
        return p
    return "unknown"

  def _is_permitted(self, tool_name: str, target: str, permission_type: str) -> bool:
    if permission_type == "read":
      return self._perm.can_read(target)
    elif permission_type == "write":
      return self._perm.can_write(target)
    elif permission_type == "shell":
      return self._perm.can_shell(target)
    elif permission_type == "list":
      return self._perm.can_list(target)
    return False

  def _create_request(
      self, tool_name, target, permission_type, reason, context_summary
  ) -> EscalationRequest:
    req = EscalationRequest(
        request_id=str(uuid.uuid4()),
        tool_name=tool_name,
        requested_path=target,
        permission_type=permission_type,
        reason=reason,
        context_summary=context_summary,
    )
    with self._lock:
      self._pending[req.request_id] = req
    self._audit("ESCALATION_REQUEST", {
      "request_id": req.request_id,
      "tool_name": tool_name,
      "requested_path": target,
      "permission_type": permission_type,
      "reason": reason,
    })
    return req
