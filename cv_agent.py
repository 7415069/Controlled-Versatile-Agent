import queue
import sys
import threading
from tkinter import messagebox

import customtkinter as ctk

from core.shell import UniversalShell

# --- 现代配色方案 (深色 IDE 风格) ---
COLOR_BG = "#1A1B1E"  # 深色背景
COLOR_SIDEBAR = "#25262B"  # 侧边栏稍亮
COLOR_ACCENT = "#339AF0"  # 蓝色点缀
COLOR_TEXT_MAIN = "#E9ECEF"  # 主文字色
COLOR_TEXT_DIM = "#909296"  # 次要文字色
COLOR_CODE_CYAN = "#9CDCFE"  # 代码淡蓝色
COLOR_SYS_GREEN = "#6A9955"  # 系统日志绿色

ctk.set_appearance_mode("dark")


class CvaUltraGui:
  def __init__(self, root):
    self.root = root
    self.root.title("CVA v2 | 系统架构师控制台")
    self.root.geometry("1150x800")
    self.root.configure(fg_color=COLOR_BG)

    self.msg_queue = queue.Queue()
    self.input_event = threading.Event()
    self.user_input_value = ""

    # --- 1. 字体精细化初始化 ---
    # 自动识别系统平台，选择最佳字体
    if sys.platform == "win32":
      self.font_family_ui = "Microsoft YaHei"
      self.font_family_mono = "Monospace"
    elif sys.platform == "darwin":  # macOS
      self.font_family_ui = "PingFang SC"
      self.font_family_mono = "Menlo"
    else:  # Linux
      self.font_family_ui = "Sans Serif"
      self.font_family_mono = "Monospace"

    # 定义几种常用的字体对象
    self.font_ui_large = (self.font_family_ui, 11)
    self.font_ui_normal = (self.font_family_ui, 10)
    self.font_ui_bold = (self.font_family_ui, 10, "bold")
    self.font_ui_small = (self.font_family_ui, 9)
    self.font_mono = (self.font_family_mono, 9)

    # 布局配置
    self.root.grid_columnconfigure(1, weight=1)
    self.root.grid_rowconfigure(0, weight=1)

    self._setup_sidebar()
    self._setup_main_chat()

    # 启动队列监听循环
    self.root.after(100, self._process_queue)

  def _setup_sidebar(self):
    """侧边栏布局：统一使用无衬线现代字体"""
    self.sidebar_frame = ctk.CTkFrame(self.root, width=280, corner_radius=0, fg_color=COLOR_SIDEBAR, border_width=0)
    self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
    self.sidebar_frame.grid_rowconfigure(10, weight=1)

    # Logo 部分
    self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="CVA SYSTEM", font=ctk.CTkFont(family=self.font_family_ui, size=24, weight="bold"), text_color=COLOR_ACCENT)
    self.logo_label.grid(row=0, column=0, padx=30, pady=(40, 30))

    # 参数区域
    self._create_label(self.sidebar_frame, "配置文件 (YAML)", 1)
    self.manifest_entry = self._create_entry(self.sidebar_frame, "roles/developer-v1.yaml", 2)

    self._create_label(self.sidebar_frame, "智能底座 (LiteLLM)", 3)
    self.model_entry = self._create_entry(self.sidebar_frame, "deepseek/deepseek-chat", 4)

    # 启动按钮
    self.start_btn = ctk.CTkButton(self.sidebar_frame, text="启动系统", height=45, font=ctk.CTkFont(family=self.font_family_mono, size=16, weight="bold"), fg_color=COLOR_ACCENT, hover_color="#228BE6", command=self._start_agent_thread)
    self.start_btn.grid(row=5, column=0, padx=30, pady=30)

    # 底部状态
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
    """右侧主界面：混合字体对话显示"""
    self.main_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
    self.main_frame.grid(row=0, column=1, padx=30, pady=30, sticky="nsew")
    self.main_frame.grid_rowconfigure(0, weight=1)
    self.main_frame.grid_columnconfigure(0, weight=1)

    # 对话显示区
    self.chat_display = ctk.CTkTextbox(self.main_frame, corner_radius=15, fg_color=COLOR_SIDEBAR, border_width=1, border_color="#373A40", text_color="#C1C2C5")
    self.chat_display.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 25))

    # --- 配置多样式标签 ---
    # body: 正常的对话，用无衬线体
    self.chat_display._textbox.tag_config("body", font=self.font_ui_normal, spacing1=8, spacing3=8)
    # code: 工具调用和JSON，用等宽体
    self.chat_display._textbox.tag_config("code", font=self.font_mono, foreground=COLOR_CODE_CYAN, spacing1=2, spacing3=2)
    # system: 内存和Session提示，用淡色等宽体
    self.chat_display._textbox.tag_config("system", font=self.font_mono, foreground=COLOR_SYS_GREEN)
    # user: 用户自己的话，加粗
    self.chat_display._textbox.tag_config("user", font=self.font_ui_bold, foreground=COLOR_ACCENT)

    self.chat_display.configure(state="disabled")

    # 底部输入区
    self.input_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
    self.input_container.grid(row=1, column=0, sticky="ew")
    self.input_container.grid_columnconfigure(0, weight=1)

    self.input_field = ctk.CTkEntry(self.input_container, placeholder_text="向 Agent 发送指令...", height=50, font=ctk.CTkFont(family=self.font_family_ui, size=16), fg_color=COLOR_SIDEBAR, border_color="#373A40", border_width=1, corner_radius=10)
    self.input_field.grid(row=0, column=0, sticky="ew", padx=(0, 15))
    self.input_field.bind("<Return>", lambda e: self._on_send())

    self.send_btn = ctk.CTkButton(self.input_container, text="发送", width=110, height=50, fg_color=COLOR_ACCENT, corner_radius=10, font=ctk.CTkFont(family=self.font_family_mono, size=16, weight="bold"), command=self._on_send)
    self.send_btn.grid(row=0, column=1)

  def _write_output(self, text):
    """智能样式分类写入"""
    self.chat_display.configure(state="normal")

    lines = text.split('\n')
    for line in lines:
      stripped = line.strip()
      if not stripped:
        self.chat_display.insert("end", "\n")
        continue

      # 样式路由逻辑
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
    self.status_dot.configure(text_color="#40C057")  # 变绿（在线）
    self.status_label.configure(text=f"在线: {model_name[:15]}...", text_color=COLOR_TEXT_MAIN)

    thread = threading.Thread(target=self._run_agent, args=(manifest, model_name), daemon=True)
    thread.start()

  def _run_agent(self, manifest_path, model_name):
    class GuiShell(UniversalShell):
      def __init__(self, outer, *args, **kwargs):
        self.outer = outer
        super().__init__(*args, **kwargs)

      def _safe_input(self, _prompt: str):
        self.outer.msg_queue.put(('print', _prompt))
        self.outer.input_event.wait()
        val = self.outer.user_input_value
        self.outer.input_event.clear()
        return val

    class StdoutRedirector:
      def __init__(self, q):
        self.q = q

      def write(self, s):
        if s.strip():
          self.q.put(('print', s))

      def flush(self):
        pass

    sys.stdout = StdoutRedirector(self.msg_queue)

    try:
      shell = GuiShell(outer=self, manifest_path=manifest_path, model=model_name)
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
