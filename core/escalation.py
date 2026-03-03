"""
权限申请管理器（Escalation Manager）v3.1 - 增强版
流程：越权拦截 → LLM 自我二次确认 → 必须则人类审批 → 即时赋能

新增功能：
- 重复申请检测：避免重复审批相同权限
- 权限有效期：自动撤销过期权限
- 审批历史记录：追踪所有审批决策
"""

import fnmatch
import os
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
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
  expires_at: Optional[str] = None  # 权限过期时间


@dataclass
class PreScreenResult:
  is_necessary: bool
  reasoning: str
  alternative: str = ""


@dataclass
class ApprovalRecord:
  """审批记录"""
  request_id: str
  tool_name: str
  requested_path: str
  permission_type: str
  status: EscalationStatus
  approved_at: str
  expires_at: Optional[str]
  approved_paths: List[str]


class EscalationManager:
  def __init__(
      self,
      policy: EscalationPolicy,
      permission_checker: PermissionChecker,
      audit_log_fn: Callable,
      llm_call_fn: Optional[Callable] = None,
      permission_ttl_hours: int = 24,  # 权限有效期（小时）
      use_gui: bool = True,
  ):
    self._policy = policy
    self._perm = permission_checker
    self._audit = audit_log_fn
    self._llm_call = llm_call_fn
    self._permission_ttl_hours = permission_ttl_hours

    self._pending: Dict[str, EscalationRequest] = {}
    self._approval_history: List[ApprovalRecord] = []  # 审批历史
    self._lock = threading.Lock()
    self._use_gui = use_gui

  def set_llm_call_fn(self, fn: Callable):
    self._llm_call = fn

  def check(self, tool_name: str, target: str, permission_type: str, reason: str = "", context_summary: str = "") -> tuple[bool, Optional[str]]:
    # 1. 检查自动拒绝模式
    if self._matches_auto_deny(target):
      self._audit("AUTO_DENIED", {"tool_name": tool_name, "target": target})
      return False, f"访问被自动拒绝：路径 `{target}` 命中安全黑名单。"

    # 2. 检查是否已有权限
    if self._is_permitted(tool_name, target, permission_type):
      return True, None

    # 3. 检查是否有重复的已批准申请
    duplicate_record = self._find_duplicate_approval(tool_name, target, permission_type)
    if duplicate_record:
      # 检查是否过期
      if not self._is_expired(duplicate_record):
        # 自动批准重复申请
        self._audit("AUTO_APPROVED_DUPLICATE", {
          "request_id": duplicate_record.request_id,
          "tool_name": tool_name,
          "target": target,
          "original_approved_at": duplicate_record.approved_at
        })
        return True, None
      else:
        # 权限已过期，需要重新申请
        self._revoke_expired_permission(duplicate_record)

    # 4. 创建新的越权申请
    req = self._create_request(tool_name, target, permission_type, reason, context_summary)

    # 5. LLM 二次确认
    pre_screen = self._llm_pre_screen(req)
    req.llm_pre_screen_result = "necessary" if pre_screen.is_necessary else "unnecessary"
    req.llm_pre_screen_reason = pre_screen.reasoning

    if not pre_screen.is_necessary:
      req.status = EscalationStatus.LLM_SELF_DENIED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      req.deny_reason = f"LLM 自我评估：不必须。{pre_screen.reasoning}"
      self._audit("LLM_SELF_DENIED", {"request_id": req.request_id, "llm_reasoning": pre_screen.reasoning})
      return False, f"越权访问 `{target}` 已被智能降级拒绝。\n理由：{pre_screen.reasoning}"

    # 6. 人类审批
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

      # 设置权限过期时间
      expires_at = datetime.now(timezone.utc) + timedelta(hours=self._permission_ttl_hours)
      req.expires_at = expires_at.isoformat()

      paths = approved_paths if approved_paths else [req.requested_path]
      req.approved_paths = paths

      # 授予权限
      if req.permission_type in ("read", "list"):
        self._perm.grant_read(paths)
      elif req.permission_type == "write":
        self._perm.grant_write(paths)
        self._perm.grant_read(paths)
      elif req.permission_type == "shell":
        self._perm.grant_shell(paths)

      # 记录审批历史
      self._record_approval(req)

      self._audit("ESCALATION_APPROVED", {
        "request_id": request_id,
        "approved_paths": paths,
        "expires_at": req.expires_at
      })

  def deny(self, request_id: str, reason: str = ""):
    with self._lock:
      req = self._pending.get(request_id)
      if not req:
        return
      req.status = EscalationStatus.DENIED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      req.deny_reason = reason
      self._audit("ESCALATION_DENIED", {"request_id": request_id, "deny_reason": reason})

  def cleanup_expired_permissions(self):
    """清理过期的权限"""
    with self._lock:
      expired_records = [r for r in self._approval_history if self._is_expired(r)]

      for record in expired_records:
        self._revoke_expired_permission(record)
        self._approval_history.remove(record)

        self._audit("PERMISSION_EXPIRED", {
          "request_id": record.request_id,
          "tool_name": record.tool_name,
          "target": record.requested_path,
          "expired_at": record.expires_at
        })

  def get_approval_history(self) -> List[ApprovalRecord]:
    """获取审批历史"""
    with self._lock:
      return list(self._approval_history)

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
    if not self._use_gui:
      return None
      # 自动检测无头环境
    if os.environ.get("DISPLAY") is None and sys.platform != "win32":
      return None
    try:
      import tkinter as tk
      from tkinter import messagebox, simpledialog

      root = tk.Tk()
      root.withdraw()  # 隐藏主窗口

      # ─── 修复：让弹窗真正居中 ───
      root.update_idletasks()

      # 获取屏幕宽高
      screen_width = root.winfo_screenwidth()
      screen_height = root.winfo_screenheight()

      # 设置一个合理的窗口大小（用于计算居中位置）
      window_width = 500
      window_height = 300

      # 计算居中位置（窗口中心 = 屏幕中心）
      x = (screen_width - window_width) // 2
      y = (screen_height - window_height) // 2

      # 设置窗口位置
      root.geometry(f"{window_width}x{window_height}+{x}+{y}")
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

      if choice:
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
    req = EscalationRequest(
        request_id=str(uuid.uuid4()),
        tool_name=tool_name,
        requested_path=target,
        permission_type=permission_type,
        reason=reason,
        context_summary=context_summary
    )
    with self._lock:
      self._pending[req.request_id] = req
    self._audit("ESCALATION_REQUEST", {
      "request_id": req.request_id,
      "tool_name": tool_name,
      "path": target
    })
    return req

  def _find_duplicate_approval(self, tool_name: str, target: str, permission_type: str) -> Optional[ApprovalRecord]:
    """查找重复的已批准申请"""
    for record in self._approval_history:
      if (record.tool_name == tool_name and
          record.requested_path == target and
          record.permission_type == permission_type and
          record.status == EscalationStatus.APPROVED):
        return record
    return None

  def _is_expired(self, record: ApprovalRecord) -> bool:
    """检查审批记录是否过期"""
    if not record.expires_at:
      return False
    try:
      expires_at = datetime.fromisoformat(record.expires_at)
      return datetime.now(timezone.utc) > expires_at
    except:
      return False

  def _record_approval(self, req: EscalationRequest):
    """记录审批历史"""
    record = ApprovalRecord(
        request_id=req.request_id,
        tool_name=req.tool_name,
        requested_path=req.requested_path,
        permission_type=req.permission_type,
        status=req.status,
        approved_at=req.decision_time or datetime.now(timezone.utc).isoformat(),
        expires_at=req.expires_at,
        approved_paths=req.approved_paths
    )
    self._approval_history.append(record)

    # 限制历史记录数量
    if len(self._approval_history) > 1000:
      self._approval_history = self._approval_history[-500:]

  def _revoke_expired_permission(self, record: ApprovalRecord):
    """撤销过期的权限"""
    if record.permission_type in ("read", "list"):
      self._perm.revoke_read(record.approved_paths)
    elif record.permission_type == "write":
      self._perm.revoke_write(record.approved_paths)
    elif record.permission_type == "shell":
      self._perm.revoke_shell(record.approved_paths)
