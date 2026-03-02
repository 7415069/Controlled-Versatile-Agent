"""
权限申请管理器（Escalation Manager）v3.2 - GUI增强版
流程：越权拦截 → LLM 自我二次确认 → 必须则人类审批 → 即时赋能

新增功能：
- 重复申请检测：避免重复审批相同权限
- 权限有效期：自动撤销过期权限
- 审批历史记录：追踪所有审批决策
- GUI增强：多屏幕居中 + 强制输入接管
"""

import fnmatch
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
      permission_ttl_hours: int = 24  # 权限有效期（小时）
  ):
    self._policy = policy
    self._perm = permission_checker
    self._audit = audit_log_fn
    self._llm_call = llm_call_fn
    self._permission_ttl_hours = permission_ttl_hours

    self._pending: Dict[str, EscalationRequest] = {}
    self._approval_history: List[ApprovalRecord] = []  # 审批历史
    self._lock = threading.Lock()

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
    """尝试使用 Tkinter 弹出居中的审批窗口（多屏幕支持 + 强制输入接管）"""
    try:
      import tkinter as tk
      from tkinter import messagebox, simpledialog

      root = tk.Tk()
      root.withdraw()  # 隐藏主窗口

      # ─── 多屏幕居中 + 强制输入接管 ───
      root.update_idletasks()

      # 获取鼠标当前位置（用于确定在哪个屏幕上显示）
      mouse_x = root.winfo_pointerx()
      mouse_y = root.winfo_pointery()

      # 获取所有屏幕信息
      try:
        # 尝试获取多屏幕信息（Tkinter 8.6+）
        screens = []
        for i in range(10):  # 最多检查10个屏幕
          try:
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()
            # 简化处理：使用主屏幕
            screens.append({
              'x': 0,
              'y': 0,
              'width': screen_width,
              'height': screen_height
            })
            break
          except:
            break
      except:
        # 回退到单屏幕模式
        screens = [{
          'x': 0,
          'y': 0,
          'width': root.winfo_screenwidth(),
          'height': root.winfo_screenheight()
        }]

      # 确定目标屏幕（鼠标所在的屏幕）
      target_screen = screens[0]
      for screen in screens:
        if (screen['x'] <= mouse_x < screen['x'] + screen['width'] and
            screen['y'] <= mouse_y < screen['y'] + screen['height']):
          target_screen = screen
          break

      # 设置窗口大小
      window_width = 550
      window_height = 350

      # 在目标屏幕上居中
      x = target_screen['x'] + (target_screen['width'] - window_width) // 2
      y = target_screen['y'] + (target_screen['height'] - window_height) // 2

      # 设置窗口位置
      root.geometry(f"{window_width}x{window_height}+{x}+{y}")

      # ─── 强制输入接管 ───
      # 1. 窗口置顶
      root.attributes('-topmost', True)
      root.lift()
      root.attributes('-topmost', False)  # 先置顶再取消，确保窗口在最上层

      # 2. 强制获取焦点
      root.focus_force()

      # 3. 捕获所有键盘和鼠标输入
      root.grab_set()

      # 4. 设置窗口类型为对话框（在KDE中更突出）
      try:
        root.attributes('-type', 'dialog')
      except:
        pass  # 某些系统不支持此属性

      # 5. 禁用窗口装饰（可选，让窗口更突出）
      # root.overrideredirect(True)  # 取消注释可去除标题栏

      # 6. 确保窗口可见
      root.deiconify()
      root.update()

      # 7. 再次强制获取焦点（确保生效）
      root.after(100, lambda: root.focus_force())
      # ─────────────────────────────

      info_text = (
        f"工具: {req.tool_name}\n类型: {req.permission_type.upper()}\n"
        f"路径: {req.requested_path}\n\n理由: {req.reason or '未说明'}"
      )

      # 创建自定义对话框以更好地控制焦点
      choice = self._show_custom_dialog(root, req, info_text)

      # 释放输入捕获
      root.grab_release()
      root.destroy()

      return choice

    except Exception as e:
      # GUI失败，回退到控制台
      print(f"[GUI] 弹窗失败: {e}")
      return None

  def _show_custom_dialog(self, root: 'tk.Tk', req: EscalationRequest, info_text: str) -> tuple[bool, str]:
    """显示自定义对话框，确保焦点正确"""
    import tkinter as tk
    from tkinter import ttk

    # 创建对话框窗口
    dialog = tk.Toplevel(root)
    dialog.title("🔐 CVA 权限申请")
    dialog.geometry("500x300")
    dialog.resizable(False, False)

    # 强制对话框属性
    dialog.transient(root)  # 设置为临时窗口
    dialog.grab_set()  # 捕获所有输入
    dialog.focus_force()  # 强制获取焦点
    dialog.attributes('-topmost', True)  # 置顶

    # 居中显示
    dialog.update_idletasks()
    x = root.winfo_x() + (root.winfo_width() - 500) // 2
    y = root.winfo_y() + (root.winfo_height() - 300) // 2
    dialog.geometry(f"500x300+{x}+{y}")

    # 结果存储
    result = {'choice': None, 'reason': '', 'new_path': ''}

    # 创建界面
    frame = ttk.Frame(dialog, padding="20")
    frame.pack(fill=tk.BOTH, expand=True)

    # 标题
    title_label = ttk.Label(frame, text="⚠️ 权限申请需要您的批准", font=('Arial', 14, 'bold'))
    title_label.pack(pady=(0, 15))

    # 信息文本
    info_label = ttk.Label(frame, text=info_text, justify=tk.LEFT, font=('Arial', 10))
    info_label.pack(pady=(0, 20), fill=tk.X)

    # 按钮框架
    button_frame = ttk.Frame(frame)
    button_frame.pack(fill=tk.X, pady=(10, 0))

    # 批准按钮
    def on_approve():
      result['choice'] = True
      dialog.destroy()

    approve_btn = ttk.Button(button_frame, text="✅ 批准", command=on_approve, width=15)
    approve_btn.pack(side=tk.LEFT, padx=(0, 10))

    # 拒绝按钮
    def on_deny():
      # 弹出拒绝理由输入框
      reason_dialog = tk.Toplevel(dialog)
      reason_dialog.title("拒绝理由")
      reason_dialog.geometry("400x150")
      reason_dialog.transient(dialog)
      reason_dialog.grab_set()
      reason_dialog.focus_force()

      reason_frame = ttk.Frame(reason_dialog, padding="15")
      reason_frame.pack(fill=tk.BOTH, expand=True)

      ttk.Label(reason_frame, text="请输入拒绝原因:").pack(anchor=tk.W, pady=(0, 5))
      reason_entry = ttk.Entry(reason_frame, width=40)
      reason_entry.pack(fill=tk.X, pady=(0, 10))
      reason_entry.focus_force()

      def submit_reason():
        result['reason'] = reason_entry.get().strip()
        result['choice'] = False
        reason_dialog.destroy()
        dialog.destroy()

      def cancel_reason():
        result['reason'] = '人类直接拒绝'
        result['choice'] = False
        reason_dialog.destroy()
        dialog.destroy()

      btn_frame = ttk.Frame(reason_frame)
      btn_frame.pack(fill=tk.X)
      ttk.Button(btn_frame, text="确定", command=submit_reason, width=10).pack(side=tk.LEFT, padx=(0, 5))
      ttk.Button(btn_frame, text="取消", command=cancel_reason, width=10).pack(side=tk.LEFT)

      reason_entry.bind('<Return>', lambda e: submit_reason())
      reason_entry.bind('<Escape>', lambda e: cancel_reason())

    deny_btn = ttk.Button(button_frame, text="❌ 拒绝", command=on_deny, width=15)
    deny_btn.pack(side=tk.LEFT, padx=(0, 10))

    # 修改路径按钮
    def on_modify():
      # 弹出路径修改输入框
      path_dialog = tk.Toplevel(dialog)
      path_dialog.title("修改路径")
      path_dialog.geometry("500x150")
      path_dialog.transient(dialog)
      path_dialog.grab_set()
      path_dialog.focus_force()

      path_frame = ttk.Frame(path_dialog, padding="15")
      path_frame.pack(fill=tk.BOTH, expand=True)

      ttk.Label(path_frame, text="请输入批准的路径（多个路径用逗号分隔）:").pack(anchor=tk.W, pady=(0, 5))
      path_entry = ttk.Entry(path_frame, width=50)
      path_entry.insert(0, req.requested_path)
      path_entry.pack(fill=tk.X, pady=(0, 10))
      path_entry.focus_force()
      path_entry.select_range(0, tk.END)

      def submit_path():
        new_path = path_entry.get().strip()
        if new_path:
          paths = [p.strip() for p in new_path.split(",") if p.strip()]
          self.approve(req.request_id, paths)
          result['choice'] = True
        else:
          result['choice'] = False
          result['reason'] = '路径为空，视为拒绝'
        path_dialog.destroy()
        dialog.destroy()

      def cancel_path():
        result['choice'] = False
        result['reason'] = '取消修改'
        path_dialog.destroy()
        dialog.destroy()

      btn_frame = ttk.Frame(path_frame)
      btn_frame.pack(fill=tk.X)
      ttk.Button(btn_frame, text="确定", command=submit_path, width=10).pack(side=tk.LEFT, padx=(0, 5))
      ttk.Button(btn_frame, text="取消", command=cancel_path, width=10).pack(side=tk.LEFT)

      path_entry.bind('<Return>', lambda e: submit_path())
      path_entry.bind('<Escape>', lambda e: cancel_path())

    modify_btn = ttk.Button(button_frame, text="✏️ 修改路径", command=on_modify, width=15)
    modify_btn.pack(side=tk.LEFT)

    # 快捷键绑定
    dialog.bind('<y>', lambda e: on_approve())
    dialog.bind('<Y>', lambda e: on_approve())
    dialog.bind('<n>', lambda e: on_deny())
    dialog.bind('<N>', lambda e: on_deny())
    dialog.bind('<m>', lambda e: on_modify())
    dialog.bind('<M>', lambda e: on_modify())
    dialog.bind('<Escape>', lambda e: on_deny())

    # 等待对话框关闭
    dialog.wait_window()

    # 处理结果
    if result['choice'] is True:
      return True, ""
    elif result['choice'] is False:
      if result['reason']:
        self.deny(req.request_id, result['reason'])
      return False, result['reason'] or "访问被拒绝"
    else:
      # 窗口被关闭，视为拒绝
      self.deny(req.request_id, "窗口被关闭")
      return False, "窗口被关闭"

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
