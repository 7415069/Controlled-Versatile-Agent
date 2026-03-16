"""
cv_agent.py — CVA GUI 入口

修复 P0-3：原来 escalation.py 的 _try_gui_approval() 在 Agent 子线程直接创建 tk.Tk()，
            违反 Tkinter 线程安全规则，导致 GUI 模式下进程崩溃。

解决方案：
  1. 主线程（CvaUltraGui）提供 _gui_approval() 方法作为弹窗实现。
  2. 通过 threading.Event + 共享变量，让 Agent 子线程等待主线程的弹窗结果。
  3. UniversalShell 构造时注入 gui_approval_fn=self._gui_approval，
     EscalationManager 在需要弹窗时回调此函数，由主线程安全地显示对话框。
"""
import difflib
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
from typing import Optional

import customtkinter as ctk

from brtech_cva.core.logger import install_print_capture
from brtech_cva.core.shell import UniversalShell

# --- 现代配色方案 (深色 IDE 风格) ---
COLOR_BG = "#1A1B1E"
COLOR_SIDEBAR = "#25262B"
COLOR_ACCENT = "#339AF0"
COLOR_TEXT_MAIN = "#E9ECEF"
COLOR_TEXT_DIM = "#909296"
COLOR_CODE_CYAN = "#9CDCFE"
COLOR_SYS_GREEN = "#6A9955"

ctk.set_appearance_mode("dark")


class DiffDialog(ctk.CTkToplevel):
  def __init__(self, master, title, old_content, new_content, on_close):
    super().__init__(master)
    self.title(title)
    self.geometry("1200x800")
    self.on_close = on_close  # 回调函数，返回 (bool, str)
    self.result = (False, "User closed window")

    # 允许窗口层级置顶并捕获焦点
    self.attributes("-topmost", True)
    self.grab_set()

    # 布局配置
    self.grid_columnconfigure(0, weight=1)
    self.grid_columnconfigure(1, weight=1)
    self.grid_rowconfigure(1, weight=1)

    # 1. 顶部标题和说明
    self.header = ctk.CTkLabel(self, text="⚠️ 请核对代码变更 (左侧: 旧内容 | 右侧: 新内容)", font=("Arial", 16, "bold"), text_color="#339AF0")
    self.header.grid(row=0, column=0, columnspan=2, pady=10)

    # 2. 中间双栏对比区
    # 使用标准的 tk.Text 因为它对 Tag 高亮的支持比 CTkTextbox 更底层且稳定
    self.left_text = tk.Text(self, bg="#1A1B1E", fg="#E9ECEF", font=("Consolas", 11), undo=False)
    self.right_text = tk.Text(self, bg="#1A1B1E", fg="#E9ECEF", font=("Consolas", 11), undo=False)

    self.left_text.grid(row=1, column=0, sticky="nsew", padx=(10, 2), pady=10)
    self.right_text.grid(row=1, column=1, sticky="nsew", padx=(2, 10), pady=10)

    # 定义高亮标签
    self.left_text.tag_config("removed", background="#442222")  # 深红背景
    self.right_text.tag_config("added", background="#224422")  # 深绿背景
    self.left_text.tag_config("header", foreground="#555555")

    # 3. 同步滚动逻辑
    self.scrollbar = ctk.CTkScrollbar(self, command=self._on_scrollbar)
    self.scrollbar.grid(row=1, column=2, sticky="ns")
    self.left_text.config(yscrollcommand=self.scrollbar.set)
    self.right_text.config(yscrollcommand=self.scrollbar.set)

    # 4. 填充差异数据
    self._fill_diff(old_content, new_content)

    # 5. 底部按钮区
    self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
    self.btn_frame.grid(row=2, column=0, columnspan=2, pady=20)

    self.approve_btn = ctk.CTkButton(self.btn_frame, text="确认修改 (Y)", fg_color="#40C057",
                                     command=lambda: self._finish(True, ""))
    self.approve_btn.pack(side="left", padx=20)

    self.deny_btn = ctk.CTkButton(self.btn_frame, text="拒绝修改 (N)", fg_color="#FA5252",
                                  command=lambda: self._finish(False, "User denied changes"))
    self.deny_btn.pack(side="left", padx=20)

    # 绑定快捷键
    self.bind("<y>", lambda e: self._finish(True, ""))
    self.bind("<n>", lambda e: self._finish(False, "User denied changes"))

  def _on_scrollbar(self, *args):
    """同步滚动两个文本框"""
    self.left_text.yview(*args)
    self.right_text.yview(*args)

  def _fill_diff(self, old_text, new_text):
    s = difflib.SequenceMatcher(None, old_text.splitlines(), new_text.splitlines())

    for tag, i1, i2, j1, j2 in s.get_opcodes():
      if tag == 'equal':
        for i in range(i1, i2):
          line = s.a[i] + "\n"
          self.left_text.insert("end", line)
          self.right_text.insert("end", line)
      elif tag == 'replace':
        for i in range(i1, i2):
          self.left_text.insert("end", s.a[i] + "\n", "removed")
        for j in range(j1, j2):
          self.right_text.insert("end", s.b[j] + "\n", "added")
      elif tag == 'delete':
        for i in range(i1, i2):
          self.left_text.insert("end", s.a[i] + "\n", "removed")
          self.right_text.insert("end", "\n")  # 保持行对齐
      elif tag == 'insert':
        for j in range(j1, j2):
          self.left_text.insert("end", "\n")  # 保持行对齐
          self.right_text.insert("end", s.b[j] + "\n", "added")

    self.left_text.config(state="disabled")
    self.right_text.config(state="disabled")

  def _finish(self, approved, message):
    self.result = (approved, message)
    self.grab_release()
    self.destroy()
    if self.on_close:
      self.on_close(self.result)


class CvaUltraGui:
  def __init__(self, root):
    self.root = root
    self.root.title("CVA | 控制台")
    self.root.geometry("1150x800")
    self.root.configure(fg_color=COLOR_BG)

    self.msg_queue = queue.Queue()
    self.input_event = threading.Event()
    self.user_input_value = ""

    # ── 修复 P0-3：主线程弹窗所需的同步原语 ──
    self._approval_request_queue: queue.Queue = queue.Queue()
    self._approval_result_event = threading.Event()
    self._approval_result: Optional[tuple] = None

    # 字体初始化
    if sys.platform == "win32":
      self.font_family_ui = "Microsoft YaHei"
      self.font_family_mono = "Monospace"
    elif sys.platform == "darwin":
      self.font_family_ui = "PingFang SC"
      self.font_family_mono = "Menlo"
    else:
      self.font_family_ui = "Sans Serif"
      self.font_family_mono = "Monospace"

    self.font_ui_large = (self.font_family_ui, 11)
    self.font_ui_normal = (self.font_family_ui, 10)
    self.font_ui_bold = (self.font_family_ui, 10, "bold")
    self.font_ui_small = (self.font_family_ui, 9)
    self.font_mono = (self.font_family_mono, 9)

    self.root.grid_columnconfigure(1, weight=1)
    self.root.grid_rowconfigure(0, weight=1)

    self._setup_sidebar()
    self._setup_main_chat()

    self.root.after(100, self._process_queue)
    self.root.after(200, self._process_approval_requests)

  def _gui_approval(self, req) -> Optional[tuple[bool, str]]:
    """
    修复 P0-3：Agent 子线程回调入口。
    将请求入队后阻塞等待，由主线程轮询弹窗后写回结果。
    """
    self._approval_result = None
    self._approval_result_event.clear()
    self._approval_request_queue.put(req)
    timeout = getattr(req, 'timeout_seconds', 300) + 10
    got_result = self._approval_result_event.wait(timeout=timeout)
    if not got_result:
      return False, "GUI 审批超时，视为拒绝"
    return self._approval_result

  def _process_approval_requests(self):
    """主线程轮询：安全地在主线程弹出 Tkinter 对话框"""
    try:
      req = self._approval_request_queue.get_nowait()
      result = self._show_approval_dialog(req)
      self._approval_result = result
      self._approval_result_event.set()
    except queue.Empty:
      pass
    finally:
      self.root.after(200, self._process_approval_requests)

  def _show_approval_dialog(self, req) -> tuple[bool, str]:
    if hasattr(req, 'diff_data') and req.diff_data:
      # 这里的 diff_data 应该是 (old_content, new_content) 的元组
      old_c, new_c = req.diff_data

      # 使用 threading.Event 等待用户在自定义窗口的操作
      res_event = threading.Event()
      final_res = [False, "Timeout"]

      def on_diff_close(result):
        final_res[0], final_res[1] = result[0], result[1]
        res_event.set()

      # 在主线程弹出 Diff 窗口
      self.root.after(0, lambda: DiffDialog(
          self.root,
          f"代码变更审查: {req.requested_path}",
          old_c, new_c,
          on_diff_close
      ))

      # 阻塞等待用户点击按钮
      res_event.wait()
      return tuple(final_res)

    else:
      info_text = (
        f"工具: {req.tool_name}\n类型: {req.permission_type.upper()}\n"
        f"路径: {req.requested_path}\n\n理由: {req.reason or '未说明'}"
      )
      choice = messagebox.askyesnocancel(
          title="🔐 CVA 权限申请",
          message=info_text,
          detail="[是] 批准  [否] 拒绝  [取消] 修改路径",
          icon="warning",
          parent=self.root,
      )
      if choice:
        return True, ""
      elif choice is False:
        deny_reason = simpledialog.askstring("拒绝理由", "请输入拒绝原因:", parent=self.root)
        return False, f"访问被拒绝: {deny_reason or ''}"
      elif choice is None:
        new_path = simpledialog.askstring("修改路径", "请输入批准的路径:",
                                          initialvalue=req.requested_path, parent=self.root)
        if new_path:
          return True, new_path
        return False, "路径为空，视为拒绝"
      return False, "未知选择"

  def _setup_sidebar(self):
    self.sidebar_frame = ctk.CTkFrame(self.root, width=280, corner_radius=0, fg_color=COLOR_SIDEBAR, border_width=0)
    self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
    self.sidebar_frame.grid_rowconfigure(10, weight=1)

    self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="CVA SYSTEM",
                                   font=ctk.CTkFont(family=self.font_family_ui, size=24, weight="bold"),
                                   text_color=COLOR_ACCENT)
    self.logo_label.grid(row=0, column=0, padx=30, pady=(40, 30))

    self._create_label(self.sidebar_frame, "配置文件 (YAML)", 1)
    self.manifest_entry = self._create_entry(self.sidebar_frame, "brtech_cva/roles/assistant.yaml", 2)
    self._create_label(self.sidebar_frame, "智能底座 (LiteLLM)", 3)
    self.model_entry = self._create_entry(self.sidebar_frame, "zai/glm-4.6v", 4)

    self.start_btn = ctk.CTkButton(
        self.sidebar_frame, text="启动系统", height=45,
        font=ctk.CTkFont(family=self.font_family_mono, size=16, weight="bold"),
        fg_color=COLOR_ACCENT, hover_color="#228BE6", command=self._start_agent_thread
    )
    self.start_btn.grid(row=5, column=0, padx=30, pady=30)

    self.status_dot = ctk.CTkLabel(self.sidebar_frame, text="●", text_color="#FA5252", font=(self.font_ui_normal, 16))
    self.status_dot.grid(row=11, column=0, padx=(30, 0), pady=20, sticky="w")
    self.status_label = ctk.CTkLabel(self.sidebar_frame, text="系统脱机", text_color=COLOR_TEXT_DIM, font=(self.font_family_mono, 16))
    self.status_label.grid(row=11, column=0, padx=(50, 20), pady=20, sticky="w")

  def _create_label(self, parent, text, row):
    label = ctk.CTkLabel(parent, text=text, font=(self.font_family_mono, 16), text_color=COLOR_TEXT_DIM)
    label.grid(row=row, column=0, padx=30, pady=(15, 0), sticky="w")

  def _create_entry(self, parent, placeholder, row):
    entry = ctk.CTkEntry(parent, placeholder_text=placeholder, width=220, height=38, fg_color="#1A1B1E", border_color="#373A40", border_width=1, font=(self.font_ui_normal, 16))
    entry.insert(0, placeholder)
    entry.grid(row=row, column=0, padx=30, pady=(5, 10))
    return entry

  def _setup_main_chat(self):
    self.main_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
    self.main_frame.grid(row=0, column=1, padx=30, pady=30, sticky="nsew")
    self.main_frame.grid_rowconfigure(0, weight=1)
    self.main_frame.grid_columnconfigure(0, weight=1)

    self.chat_display = ctk.CTkTextbox(self.main_frame, corner_radius=15, fg_color=COLOR_SIDEBAR,
                                       border_width=1, border_color="#373A40", text_color="#C1C2C5")
    self.chat_display.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 25))

    self.chat_display._textbox.tag_config("body", font=self.font_ui_normal, spacing1=8, spacing3=8)
    self.chat_display._textbox.tag_config("code", font=self.font_mono, foreground=COLOR_CODE_CYAN, spacing1=2, spacing3=2)
    self.chat_display._textbox.tag_config("system", font=self.font_mono, foreground=COLOR_SYS_GREEN)
    self.chat_display._textbox.tag_config("user", font=self.font_ui_bold, foreground=COLOR_ACCENT)
    self.chat_display.configure(state="disabled")

    self.input_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
    self.input_container.grid(row=1, column=0, sticky="ew")
    self.input_container.grid_columnconfigure(0, weight=1)

    self.input_field = ctk.CTkEntry(
        self.input_container, placeholder_text="向 Agent 发送指令...", height=50,
        font=ctk.CTkFont(family=self.font_family_ui, size=16),
        fg_color=COLOR_SIDEBAR, border_color="#373A40", border_width=1, corner_radius=10
    )
    self.input_field.grid(row=0, column=0, sticky="ew", padx=(0, 15))
    self.input_field.bind("<Return>", lambda e: self._on_send())

    self.send_btn = ctk.CTkButton(
        self.input_container, text="发送", width=110, height=50, fg_color=COLOR_ACCENT, corner_radius=10,
        font=ctk.CTkFont(family=self.font_family_mono, size=16, weight="bold"), command=self._on_send
    )
    self.send_btn.grid(row=0, column=1)

  def _write_output(self, text):
    self.chat_display.configure(state="normal")
    lines = text.split('\n')
    for line in lines:
      stripped = line.strip()
      if not stripped:
        self.chat_display.insert("end", "\n")
        continue
      if "👤 USER:" in line:
        self.chat_display.insert("end", line + "\n", "user")
      elif stripped.startswith("[") and ("]" in stripped):
        self.chat_display.insert("end", line + "\n", "system")
      elif any(sym in line for sym in ("🔧", "✔", "✖", "─", "🚀", "Command", ">", "    ", "{", "}")):
        self.chat_display.insert("end", line + "\n", "code")
      else:
        self.chat_display.insert("end", line + "\n", "body")
    self.chat_display.see("end")
    self.chat_display.configure(state="disabled")

  def _on_send(self):
    content = self.input_field.get().strip()
    if content:
      self._write_output(f"\n👤 USER: {content}")
      self.input_field.delete(0, "end")
      self.user_input_value = content
      self.input_event.set()

  def _start_agent_thread(self):
    manifest = self.manifest_entry.get().strip()
    model_name = self.model_entry.get().strip()
    if not manifest or not model_name:
      messagebox.showwarning("参数缺失", "请检查配置文件路径和模型名称")
      return
    self.start_btn.configure(state="disabled", text="系统引导中...")
    self.status_dot.configure(text_color="#40C057")
    self.status_label.configure(text=f"在线: {model_name[:15]}...", text_color=COLOR_TEXT_MAIN)
    thread = threading.Thread(target=self._run_agent, args=(manifest, model_name), daemon=True)
    thread.start()

  def _run_agent(self, manifest_path, model_name):
    install_print_capture(gui_queue=self.msg_queue)

    outer = self  # 捕获外层引用

    class GuiShell(UniversalShell):
      def _safe_input(self_inner, _prompt: str):
        outer.msg_queue.put(('print', _prompt))
        outer.input_event.wait()
        val = outer.user_input_value
        outer.input_event.clear()
        return val

    try:
      shell = GuiShell(
          manifest_path=manifest_path,
          model=model_name,
          gui_approval_fn=self._gui_approval,  # 修复 P0-3
      )
      shell.start()
    except Exception as e:
      self.msg_queue.put(('error', str(e)))

  def _process_queue(self):
    try:
      while True:
        msg_type, content = self.msg_queue.get_nowait()
        if msg_type == 'print':
          self._write_output(content)
        elif msg_type == 'error':
          messagebox.showerror("系统故障", content)
        self.msg_queue.task_done()
    except queue.Empty:
      pass
    self.root.after(100, self._process_queue)


if __name__ == "__main__":
  app_root = ctk.CTk()
  app = CvaUltraGui(app_root)
  app_root.mainloop()
