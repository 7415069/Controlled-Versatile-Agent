"""
权限申请管理器（Escalation Manager）
实现：越权拦截 → 挂起 → 人类审批 → 即时赋能 完整闭环
"""

import fnmatch
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
  TIMEOUT = "TIMEOUT"


@dataclass
class EscalationRequest:
  request_id: str
  tool_name: str
  requested_path: str  # 申请访问的路径或命令
  permission_type: str  # read / write / shell / list
  reason: str  # LLM 提供的理由
  context_summary: str  # 最近 N 轮对话摘要
  timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
  status: EscalationStatus = EscalationStatus.PENDING
  decision_time: Optional[str] = None
  approved_paths: List[str] = field(default_factory=list)
  deny_reason: Optional[str] = None


class EscalationManager:
  """
  在工具执行前拦截越权请求，通过人类审批后动态扩展权限白名单。
  """

  def __init__(
      self,
      policy: EscalationPolicy,
      permission_checker: PermissionChecker,
      audit_log_fn: Callable,  # 审计日志回调
  ):
    self._policy = policy
    self._perm = permission_checker
    self._audit = audit_log_fn
    self._pending: Dict[str, EscalationRequest] = {}
    self._lock = threading.Lock()

  # ─── 核心检查入口 ──────────────────────────────────────────

  def check(
      self,
      tool_name: str,
      target: str,
      permission_type: str,
      reason: str = "",
      context_summary: str = "",
  ) -> tuple[bool, Optional[str]]:
    """
    检查工具调用是否被允许。
    返回 (allowed: bool, deny_message: Optional[str])
    - allowed=True  → 放行
    - allowed=False → deny_message 包含向 LLM 返回的拒绝说明
    """
    # 1. 命中自动拒绝黑名单
    if self._matches_auto_deny(target):
      self._audit("AUTO_DENIED", {
        "tool_name": tool_name,
        "target": target,
        "matched_pattern": self._find_auto_deny_pattern(target),
      })
      return False, (
        f"访问被自动拒绝：路径 `{target}` 命中安全黑名单。\n"
        f"如需访问，请联系管理员修改 Manifest auto_deny_patterns 配置。"
      )

    # 2. 命中运行时白名单
    if self._is_permitted(tool_name, target, permission_type):
      return True, None

    # 3. 越权 → 发起人类审批
    req = self._create_request(tool_name, target, permission_type, reason, context_summary)
    approved, message = self._ask_human(req)

    if approved:
      return True, None
    else:
      return False, message

  # ─── 人类决策接口（供 Shell 调用）─────────────────────────

  def approve(self, request_id: str, approved_paths: Optional[List[str]] = None):
    """批准申请，将新路径写入运行时白名单"""
    with self._lock:
      req = self._pending.get(request_id)
      if not req:
        return

      req.status = EscalationStatus.APPROVED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      paths = approved_paths if approved_paths else [req.requested_path]
      req.approved_paths = paths

      # 根据权限类型扩展白名单
      if req.permission_type in ("read", "list"):
        self._perm.grant_read(paths)
      elif req.permission_type == "write":
        self._perm.grant_write(paths)
        self._perm.grant_read(paths)  # 写权限隐含读权限
      elif req.permission_type == "shell":
        self._perm.grant_shell(paths)

      self._audit("ESCALATION_APPROVED", {
        "request_id": request_id,
        "approved_paths": paths,
        "approver": "human_supervisor",
        "new_whitelist": self._perm.snapshot(),
      })

  def deny(self, request_id: str, reason: str = ""):
    """拒绝申请"""
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

  # ─── 私有方法 ─────────────────────────────────────────────

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

  def _ask_human(self, req: EscalationRequest) -> tuple[bool, str]:
    """控制台交互式审批"""
    print("\n" + "═" * 60)
    print("⚠️  [CVA 权限申请] — 需要您的授权")
    print("═" * 60)
    print(f"  申请 ID   : {req.request_id}")
    print(f"  工具      : {req.tool_name}")
    print(f"  申请路径  : {req.requested_path}")
    print(f"  权限类型  : {req.permission_type}")
    print(f"  申请理由  : {req.reason or '（未提供）'}")
    if req.context_summary:
      print(f"  上下文摘要: {req.context_summary[:200]}")
    print("─" * 60)
    print("  选项:")
    print("  [y]  批准（授予申请路径权限）")
    print("  [n]  拒绝")
    print("  [m]  修改路径后批准（输入新路径）")
    print("─" * 60)

    import signal

    # 超时处理
    timeout = self._policy.timeout_seconds

    def _timeout_handler(signum, frame):
      raise TimeoutError()

    try:
      signal.signal(signal.SIGALRM, _timeout_handler)
      signal.alarm(timeout)
      choice = input(f"  请输入选项 (超时 {timeout}s 自动拒绝): ").strip().lower()
      signal.alarm(0)
    except (TimeoutError, EOFError):
      signal.alarm(0)
      print(f"\n  [超时] {timeout}s 内未响应，自动拒绝。")
      req.status = EscalationStatus.TIMEOUT
      req.decision_time = datetime.now(timezone.utc).isoformat()
      self._audit("ESCALATION_DENIED", {
        "request_id": req.request_id,
        "deny_reason": "timeout",
      })
      return False, f"权限申请超时（{timeout}s），访问 `{req.requested_path}` 被拒绝。"

    if choice == "y":
      self.approve(req.request_id)
      print(f"  ✅ 已批准，权限白名单已更新。")
      print("═" * 60 + "\n")
      return True, ""

    elif choice == "m":
      try:
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(60)
        new_path = input("  请输入批准的路径（多个路径用逗号分隔）: ").strip()
        signal.alarm(0)
      except (TimeoutError, EOFError):
        signal.alarm(0)
        new_path = ""

      if new_path:
        paths = [p.strip() for p in new_path.split(",") if p.strip()]
        self.approve(req.request_id, paths)
        print(f"  ✅ 已批准路径: {paths}")
        print("═" * 60 + "\n")
        return True, ""
      else:
        self.deny(req.request_id, "修改路径为空，视为拒绝")
        print("  ❌ 路径为空，已拒绝。")
        print("═" * 60 + "\n")
        return False, f"访问 `{req.requested_path}` 被拒绝：修改路径为空。"

    else:
      try:
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(30)
        deny_reason = input("  拒绝原因（可选，直接回车跳过）: ").strip()
        signal.alarm(0)
      except (TimeoutError, EOFError):
        signal.alarm(0)
        deny_reason = ""

      self.deny(req.request_id, deny_reason)
      print(f"  ❌ 已拒绝。")
      print("═" * 60 + "\n")
      reason_text = f"，原因：{deny_reason}" if deny_reason else ""
      return False, f"访问 `{req.requested_path}` 被人类导师拒绝{reason_text}。"
