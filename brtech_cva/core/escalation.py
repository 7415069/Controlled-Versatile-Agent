"""
权限申请管理器（Escalation Manager）v3.2

修复内容：
  P0-3: _try_gui_approval() 在 Agent 子线程中直接创建 tk.Tk()，
        违反 Tkinter 线程安全规则，导致 GUI 模式下进程崩溃。
        → 改为通过 gui_approval_fn 回调，由主线程弹窗并返回结果。
  P2-5: _console_approval() 的 'm' 分支使用裸 input()，
        GUI 模式下 stdin 已被重定向会卡死。
        → 统一使用注入的 _input_fn（与 shell._safe_input 对齐）。
  P2-7: _rotate_log() 在 AuditLogger 的 _lock 外被调用，
        多线程并发写时可能同时 rename 同一文件。
        → _rotate_log 已在调用方 log() 的 _lock 内执行，补充注释说明。
"""

import fnmatch
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Callable, Dict, List, Optional

from brtech_cva.core.manifest import EscalationPolicy
from brtech_cva.core.permissions import PermissionChecker


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
  expires_at: Optional[str] = None
  diff: Optional[str] = None
  diff_data: Optional[tuple[str, str]] = None


@dataclass
class PreScreenResult:
  is_necessary: bool
  reasoning: str
  alternative: str = ""


@dataclass
class ApprovalRecord:
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
      permission_ttl_hours: int = 24,
      # 修复 P0-3：不再接受 use_gui 布尔参数，改为接受可选的 gui_approval_fn 回调。
      # gui_approval_fn 由主线程负责弹窗，子线程（Agent）通过此回调等待审批结果。
      # 签名：gui_approval_fn(req: EscalationRequest) -> Optional[tuple[bool, str]]
      # 返回 None 表示 GUI 不可用，降级到控制台审批。
      gui_approval_fn: Optional[Callable] = None,
      # 统一输入函数（GUI 模式传 shell._safe_input，CLI 模式传 None 使用内置 input）
      input_fn: Optional[Callable] = None,
  ):
    self._policy = policy
    self._perm = permission_checker
    self._audit = audit_log_fn
    self._llm_call = llm_call_fn
    self._permission_ttl_hours = permission_ttl_hours

    # 修复 P0-3：保存主线程弹窗回调，替代在子线程直接创建 tk.Tk()
    self._gui_approval_fn = gui_approval_fn

    # 修复 P2-5：统一输入函数
    self._input_fn = input_fn or input

    self._pending: Dict[str, EscalationRequest] = {}
    self._approval_history: List[ApprovalRecord] = []
    self._lock = threading.Lock()

  def set_llm_call_fn(self, fn: Callable):
    self._llm_call = fn

  def set_gui_approval_fn(self, fn: Optional[Callable]):
    """动态绑定主线程弹窗回调（GUI 启动后调用）"""
    self._gui_approval_fn = fn

  def check(self, tool_name: str, target: str, permission_type: str, reason: str = "", context_summary: str = "", diff: Optional[str] = None, diff_data: Optional[tuple[str, str]] = None) -> tuple[bool, Optional[str]]:
    # 1. 自动拒绝黑名单
    if self._matches_auto_deny(target):
      self._audit("AUTO_DENIED", {"tool_name": tool_name, "target": target})
      return False, f"访问被自动拒绝：路径 `{target}` 命中安全黑名单。"

    # 2. 已有权限
    if self._is_permitted(tool_name, target, permission_type):
      return True, None

    # 3. 重复申请复用
    duplicate_record = self._find_duplicate_approval(tool_name, target, permission_type)
    if duplicate_record:
      if not self._is_expired(duplicate_record):
        self._audit("AUTO_APPROVED_DUPLICATE", {
          "request_id": duplicate_record.request_id,
          "tool_name": tool_name,
          "target": target,
          "original_approved_at": duplicate_record.approved_at
        })
        return True, None
      else:
        self._revoke_expired_permission(duplicate_record)

    # 4. 创建越权申请
    req = self._create_request(tool_name, target, permission_type, reason, context_summary, diff, diff_data)

    # 5. 风险分级
    risk_level = self._classify_risk_level(tool_name, target, permission_type)
    self._audit("RISK_CLASSIFIED", {"request_id": req.request_id, "risk_level": risk_level})

    if risk_level == "LOW":
      self.approve(req.request_id)
      self._audit("AUTO_APPROVED_LOW_RISK", {"request_id": req.request_id})
      return True, None

    # 6. LLM 二次确认
    pre_screen = self._llm_pre_screen(req)
    req.llm_pre_screen_result = "necessary" if pre_screen.is_necessary else "unnecessary"
    req.llm_pre_screen_reason = pre_screen.reasoning

    if not pre_screen.is_necessary:
      req.status = EscalationStatus.LLM_SELF_DENIED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      req.deny_reason = f"LLM 自我评估：不必须。{pre_screen.reasoning}"
      self._audit("LLM_SELF_DENIED", {"request_id": req.request_id, "llm_reasoning": pre_screen.reasoning})
      return False, f"越权访问 `{target}` 已被智能降级拒绝。\n理由：{pre_screen.reasoning}"

    self._audit("LLM_PRE_SCREEN_PASSED", {"request_id": req.request_id, "risk_level": risk_level})

    if risk_level == "MEDIUM":
      self.approve(req.request_id)
      self._audit("AUTO_APPROVED_MEDIUM_RISK", {"request_id": req.request_id})
      return True, None

    # HIGH：人类审批
    approved, message = self._ask_human(req)
    return (True, None) if approved else (False, message)

  def _classify_risk_level(self, tool_name: str, target: str, permission_type: str) -> str:
    target_lower = target.lower()
    high_indicators = [
      tool_name == "execute_python_script",
      (tool_name == "run_shell" and any(
          kw in target_lower for kw in ["rm ", "dd ", "mkfs", "chmod", "chown", "sudo", "> /", ">> /"]
      )),
      any(kw in target_lower for kw in ["secret", "password", "token", "credential", ".env"]),
    ]
    if any(high_indicators):
      return "HIGH"

    if permission_type == "gui_control":
      if "click" in target or "type" in target:
        return "HIGH"
      return "MEDIUM"

    safe_prefixes = ["./core", "./tests", "./docs", "./agent_workspace", "./roles"]
    is_read_only = permission_type in ("read", "list")
    in_safe_dir = any(target.startswith(p) for p in safe_prefixes)
    if is_read_only and in_safe_dir:
      return "LOW"

    return "MEDIUM"

  def approve(self, request_id: str, approved_paths: Optional[List[str]] = None):
    with self._lock:
      req = self._pending.get(request_id)
      if not req:
        return
      req.status = EscalationStatus.APPROVED
      req.decision_time = datetime.now(timezone.utc).isoformat()
      expires_at = datetime.now(timezone.utc) + timedelta(hours=self._permission_ttl_hours)
      req.expires_at = expires_at.isoformat()
      paths = approved_paths if approved_paths else [req.requested_path]
      req.approved_paths = paths

      if req.permission_type in ("read", "list"):
        self._perm.grant_read(paths)
      elif req.permission_type == "write":
        self._perm.grant_write(paths)
        self._perm.grant_read(paths)
      elif req.permission_type == "shell":
        self._perm.grant_shell(paths)

      elif req.permission_type == "gui_control":
        self._perm.grant_gui_control(paths)

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
    with self._lock:
      return list(self._approval_history)

  def _llm_pre_screen(self, req: EscalationRequest) -> PreScreenResult:
    if not self._llm_call:
      return PreScreenResult(is_necessary=True, reasoning="二次确认不可用。")
    print(f"\n[CVA·二次确认] 🤔 正在评估必要性: {req.tool_name}({req.requested_path})")
    risk_level = self._classify_risk_level(req.tool_name, req.requested_path, req.permission_type)
    try:
      result = self._llm_call(req)
      if req.permission_type == "gui_control" and not result.is_necessary:
        return PreScreenResult(is_necessary=True, reasoning="LLM 预审建议拦截，但 GUI 操作需由人类最终裁定。")
      return result
    except Exception as e:
      if risk_level == "HIGH":
        print(f"[CVA·二次确认] ⚠️  LLM 调用失败（{e}），HIGH 风险操作升级为人类审批")
        return PreScreenResult(is_necessary=True, reasoning=f"LLM 不可用，HIGH 风险需人类确认。原始错误: {e}")
      else:
        print(f"[CVA·二次确认] ⚠️  LLM 调用失败（{e}），MEDIUM 风险保守放行")
        return PreScreenResult(is_necessary=True, reasoning=f"LLM 不可用，MEDIUM 风险保守放行。原始错误: {e}")

  def _ask_human(self, req: EscalationRequest) -> tuple[bool, str]:
    print("\n" + "═" * 60)
    print("🔐 [CVA 权限申请] — 请您裁定")
    print(f"  工具: {req.tool_name} | 路径: {req.requested_path} | 类型: {req.permission_type}")
    print(f"  理由: {req.reason or '（无）'}")
    print("─" * 60)

    # 修复 P0-3：通过注入的回调让主线程弹窗，而非在子线程直接创建 Tkinter 窗口
    if self._gui_approval_fn is not None:
      result = self._gui_approval_fn(req)
      if result is not None:
        return result

    return self._console_approval(req)

  def _console_approval(self, req: EscalationRequest) -> tuple[bool, str]:
    """
    修复 P2-5：所有 input() 调用统一替换为 self._input_fn。
    GUI 模式下 _input_fn = shell._safe_input（通过队列与主线程交互），
    CLI 模式下 _input_fn = 内置 input()，行为与修复前完全一致。
    """
    print("  选项: [y] 批准  [n] 拒绝  [m] 修改路径")
    timeout = self._policy.timeout_seconds
    choice = self._input_with_timeout(f"  请输入选项（{timeout}s 超时）: ", timeout)

    if choice is None:
      return False, "超时自动拒绝"

    c = choice.strip().lower()
    if c == 'y':
      self.approve(req.request_id)
      return True, ""
    elif c == 'm':
      # 修复 P2-5：原来这里使用裸 input()，GUI 模式下会卡死
      new_path = self._input_fn("  请输入新路径: ")
      if isinstance(new_path, str):
        new_path = new_path.strip()
      if new_path:
        self.approve(req.request_id, [new_path])
        return True, ""

    self.deny(req.request_id)
    return False, "人类拒绝"

  def _input_with_timeout(self, prompt: str, timeout: int) -> Optional[str]:
    """
    带超时的输入函数。
    使用 self._input_fn 统一处理 CLI/GUI 两种模式。
    SIGALRM 仅在 Unix + CLI 模式下有效；GUI 模式依赖主线程超时逻辑。
    """
    import signal

    if sys.platform == "win32":
      try:
        return self._input_fn(prompt)
      except Exception:
        return None

    # Unix：使用 SIGALRM 实现超时（仅在主线程有效，子线程 signal 不可用）
    # 如果 _input_fn 不是内置 input（如 GUI 模式），跳过 SIGALRM，直接调用
    if self._input_fn is not input:
      try:
        return self._input_fn(prompt)
      except Exception:
        return None

    def _h(s, f):
      raise TimeoutError()

    signal.signal(signal.SIGALRM, _h)
    signal.alarm(timeout)
    try:
      r = self._input_fn(prompt)
      signal.alarm(0)
      return r
    except Exception:
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
    elif permission_type == "gui_control":
      return self._perm.can_gui_control(target)
    return False

  def _create_request(self, tool_name, target, permission_type, reason, context_summary, diff: Optional[str] = None, diff_data: Optional[tuple[str, str]] = None) -> EscalationRequest:
    req = EscalationRequest(
        request_id=str(uuid.uuid4()),
        tool_name=tool_name,
        requested_path=target,
        permission_type=permission_type,
        reason=reason,
        context_summary=context_summary,
        diff=diff,
        diff_data=diff_data
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
    for record in self._approval_history:
      if (record.tool_name == tool_name and
          record.requested_path == target and
          record.permission_type == permission_type and
          record.status == EscalationStatus.APPROVED):
        return record
    return None

  def _is_expired(self, record: ApprovalRecord) -> bool:
    if not record.expires_at:
      return False
    try:
      expires_at = datetime.fromisoformat(record.expires_at)
      return datetime.now(timezone.utc) > expires_at
    except Exception:
      return False

  def _record_approval(self, req: EscalationRequest):
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
    if len(self._approval_history) > 1000:
      self._approval_history = self._approval_history[-500:]

  def _revoke_expired_permission(self, record: ApprovalRecord):
    if record.permission_type in ("read", "list"):
      self._perm.revoke_read(record.approved_paths)
    elif record.permission_type == "write":
      self._perm.revoke_write(record.approved_paths)
    elif record.permission_type == "shell":
      self._perm.revoke_shell(record.approved_paths)
