"""
权限申请管理器（Escalation Manager）v2
流程：越权拦截 → LLM 自我二次确认 → 必须则人类审批 → 即时赋能
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
  LLM_SELF_DENIED = "LLM_SELF_DENIED"
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
  llm_pre_screen_result: Optional[str] = None
  llm_pre_screen_reason: Optional[str] = None


@dataclass
class PreScreenResult:
  is_necessary: bool
  reasoning: str
  alternative: str = ""


class EscalationManager:
  def __init__(self, policy: EscalationPolicy, permission_checker: PermissionChecker, audit_log_fn: Callable, llm_call_fn: Optional[Callable] = None):
    self._policy = policy
    self._perm = permission_checker
    self._audit = audit_log_fn
    self._llm_call = llm_call_fn
    self._pending: Dict[str, EscalationRequest] = {}
    self._lock = threading.Lock()

  def set_llm_call_fn(self, fn: Callable):
    self._llm_call = fn

  def check(self, tool_name: str, target: str, permission_type: str, reason: str = "", context_summary: str = "") -> tuple[bool, Optional[str]]:
    if self._matches_auto_deny(target):
      self._audit("AUTO_DENIED", {"tool_name": tool_name, "target": target})
      return False, f"访问被自动拒绝：路径 `{target}` 命中安全黑名单。"

    if self._is_permitted(tool_name, target, permission_type):
      return True, None

    req = self._create_request(tool_name, target, permission_type, reason, context_summary)
    pre_screen = self._llm_pre_screen(req)
    req.llm_pre_screen_result = "necessary" if pre_screen.is_necessary else "unnecessary"
    req.llm_pre_screen_reason = pre_screen.reasoning

    if not pre_screen.is_necessary:
      req.status = EscalationStatus.LLM_SELF_DENIED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      req.deny_reason = f"LLM 自我评估：不必须。{pre_screen.reasoning}"
      self._audit("LLM_SELF_DENIED", {"request_id": req.request_id, "llm_reasoning": pre_screen.reasoning})
      return False, f"越权访问 `{target}` 已被智能降级拒绝。\n理由：{pre_screen.reasoning}"

    self._audit("LLM_PRE_SCREEN_PASSED", {"request_id": req.request_id})
    approved, message = self._ask_human(req)
    return (True, None) if approved else (False, message)

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
      self._audit("ESCALATION_APPROVED", {"request_id": request_id, "approved_paths": paths})

  def deny(self, request_id: str, reason: str = ""):
    with self._lock:
      req = self._pending.get(request_id)
      if not req:
        return
      req.status = EscalationStatus.DENIED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      req.deny_reason = reason
      self._audit("ESCALATION_DENIED", {"request_id": request_id, "deny_reason": reason})

  def _llm_pre_screen(self, req: EscalationRequest) -> PreScreenResult:
    if not self._llm_call:
      return PreScreenResult(is_necessary=True, reasoning="二次确认不可用。")
    print(f"\n[CVA·二次确认] 🤔 正在评估必要性: {req.tool_name}({req.requested_path})")
    try:
      return self._llm_call(req)
    except Exception as e:
      return PreScreenResult(is_necessary=True, reasoning=f"异常: {e}")

  def _ask_human(self, req: EscalationRequest) -> tuple[bool, str]:
    print("\n" + "═" * 60)
    print("🔐 [CVA 权限申请] — 请您裁定")
    print(f"  工具: {req.tool_name} | 路径: {req.requested_path} | 类型: {req.permission_type}")
    print(f"  理由: {req.reason or '（无）'}")
    print("─" * 60)
    gui_result = self._try_gui_approval(req)
    if gui_result is not None:
      return gui_result
    return self._console_approval(req)

  def _try_gui_approval(self, req: EscalationRequest) -> Optional[tuple[bool, str]]:
    """尝试使用 Tkinter 弹出居中的审批窗口"""
    try:
      import tkinter as tk
      from tkinter import messagebox, simpledialog

      root = tk.Tk()
      root.withdraw()  # 隐藏主窗口

      # ─── 关键修改：让弹窗居中 ───
      root.update_idletasks()
      # 获取屏幕宽高
      screen_width = root.winfo_screenwidth()
      screen_height = root.winfo_screenheight()
      # 设置 root 位置在屏幕中央，这样弹出的 messagebox 也会居中
      root.geometry(f"+{screen_width // 2}+{screen_height // 2}")
      # ─────────────────────────

      info_text = (
        f"工具: {req.tool_name}\n类型: {req.permission_type.upper()}\n"
        f"路径: {req.requested_path}\n\n理由: {req.reason or '未说明'}"
      )

      choice = messagebox.askyesnocancel(
          title="🔐 CVA 权限申请",
          message=info_text,
          detail="[是] 批准  [否] 拒绝  [取消] 修改路径",
          icon="warning",
          parent=root  # 绑定到已定位的 root
      )

      if choice is True:
        root.destroy()
        self.approve(req.request_id)
        return True, ""
      elif choice is False:
        deny_reason = simpledialog.askstring("拒绝理由", "请输入拒绝原因:", parent=root)
        root.destroy()
        self.deny(req.request_id, deny_reason or "人类直接拒绝")
        return False, f"访问被拒绝: {deny_reason or ''}"
      elif choice is None:
        new_path = simpledialog.askstring("修改路径", "请输入批准的路径:", initialvalue=req.requested_path, parent=root)
        root.destroy()
        if new_path:
          paths = [p.strip() for p in new_path.split(",") if p.strip()]
          self.approve(req.request_id, paths)
          return True, ""
        return False, "路径为空，视为拒绝"

    except Exception:
      return None

  def _console_approval(self, req: EscalationRequest) -> tuple[bool, str]:
    print("  选项: [y] 批准  [n] 拒绝  [m] 修改路径")
    timeout = self._policy.timeout_seconds
    # 注意：此处 input 处理在 shell.py 中统一加固
    choice = self._input_with_timeout(f"  请输入选项（{timeout}s 超时）: ", timeout)
    if choice is None:
      return False, "超时自动拒绝"
    c = choice.strip().lower()
    if c == 'y':
      self.approve(req.request_id)
      return True, ""
    elif c == 'm':
      new_path = input("  请输入新路径: ").strip()
      if new_path:
        self.approve(req.request_id, [new_path])
        return True, ""
    self.deny(req.request_id)
    return False, "人类拒绝"

  def _input_with_timeout(self, prompt: str, timeout: int) -> Optional[str]:
    import signal
    if sys.platform == "win32":
      # Windows 无法使用 signal.alarm，简单回退
      try:
        return input(prompt)
      except:
        return None

    def _h(s, f):
      raise TimeoutError()

    signal.signal(signal.SIGALRM, _h)
    signal.alarm(timeout)
    try:
      r = input(prompt)
      signal.alarm(0)
      return r
    except:
      signal.alarm(0)
      return None

  def _matches_auto_deny(self, target: str) -> bool:
    return any(fnmatch.fnmatch(target, p) or target.startswith(p.rstrip("*")) for p in self._policy.auto_deny_patterns)

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

  def _create_request(self, tool_name, target, permission_type, reason, context_summary) -> EscalationRequest:
    req = EscalationRequest(request_id=str(uuid.uuid4()), tool_name=tool_name, requested_path=target, permission_type=permission_type, reason=reason, context_summary=context_summary)
    with self._lock: self._pending[req.request_id] = req
    self._audit("ESCALATION_REQUEST", {"request_id": req.request_id, "tool_name": tool_name, "path": target})
    return req
