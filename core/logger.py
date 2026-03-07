# core/logger.py
"""
日志模块：统一管理所有输出。

架构：
  - sys_logger   : 标准 logging.Logger，写 system.log + 控制台（DEBUG 时也写 llm_trace.log）
  - trace_logger : 专用于 LLM payload 的 Logger，写 llm_trace.log
  - PrintCapture : 替换 sys.stdout，将所有 print() 同时写入
                   ① system.log（通过 sys_logger.info）
                   ② GUI 队列（若已注册）

使用方法：
  # 1. CLI 启动时（main/__main__）
  from core.logger import install_print_capture
  install_print_capture()          # print → 控制台 + system.log

  # 2. GUI 启动时（cv_agent.py _run_agent）
  from core.logger import install_print_capture
  install_print_capture(gui_queue=self.msg_queue)   # print → 窗口 + system.log

  # 3. 若需要手动写日志（不经过 print）
  from core.logger import sys_logger
  sys_logger.warning("something went wrong")
"""

import logging
import os
import queue
import sys
import threading
from logging.handlers import RotatingFileHandler
from typing import Optional


# ──────────────────────────────────────────────
# 1. 标准 Logger 初始化
# ──────────────────────────────────────────────

def setup_logger(log_dir: str = "var/logs/llm", level: int = logging.INFO) -> logging.Logger:
  os.makedirs(log_dir, exist_ok=True)

  logger = logging.getLogger("CVA")
  logger.setLevel(logging.DEBUG)  # 由各 handler 自行过滤

  if logger.handlers:  # 防止重复添加
    return logger

  fmt = logging.Formatter(
      "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
      datefmt="%Y-%m-%d %H:%M:%S",
  )

  # 1-a. 控制台 handler（仅 CLI 场景；GUI 场景由 PrintCapture 代劳，此处静默）
  console_handler = logging.StreamHandler()
  console_handler.setLevel(level)
  console_handler.setFormatter(fmt)

  # 1-b. system.log（所有 INFO+ 消息，含 print 重定向）
  system_file = os.path.join(log_dir, "system.log")
  file_handler = RotatingFileHandler(
      system_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
  )
  file_handler.setLevel(logging.INFO)
  file_handler.setFormatter(fmt)

  logger.addHandler(console_handler)
  logger.addHandler(file_handler)

  # 1-c. llm_trace.log（LLM payload 专用）
  trace_file = os.path.join(log_dir, "llm_trace.log")
  trace_handler = RotatingFileHandler(
      trace_file, maxBytes=20 * 1024 * 1024, backupCount=5, encoding="utf-8"
  )
  trace_handler.setLevel(logging.DEBUG)
  trace_handler.setFormatter(fmt)

  trace_logger = logging.getLogger("CVA.TRACE")
  trace_logger.propagate = False
  trace_logger.addHandler(trace_handler)
  # DEBUG 模式下 trace 也输出到控制台
  if level == logging.DEBUG:
    trace_logger.addHandler(console_handler)

  return logger


# ──────────────────────────────────────────────
# 2. PrintCapture：拦截 sys.stdout
# ──────────────────────────────────────────────

class PrintCapture:
  """
  替换 sys.stdout，将所有 print() 输出同时发往：
    - system.log（通过 sys_logger.info）
    - GUI 队列（若提供，格式为 ('print', text)）
    - 原始 stdout（CLI 场景下保留终端输出）

  线程安全：内部使用 _lock 序列化写操作。
  """

  def __init__(
      self,
      logger: logging.Logger,
      original_stdout,
      gui_queue: Optional[queue.Queue] = None,
      keep_stdout: bool = True,
  ):
    self._logger = logger
    self._original_stdout = original_stdout
    self._gui_queue = gui_queue
    self._keep_stdout = keep_stdout
    self._lock = threading.Lock()
    self._buf = ""  # 行缓冲，处理不带换行符的碎片 write()

  # ── 注册 / 注销 GUI 队列（线程安全）──

  def set_gui_queue(self, q: Optional[queue.Queue]) -> None:
    """动态绑定或解绑 GUI 队列（可在 Agent 线程启动后调用）。"""
    with self._lock:
      self._gui_queue = q

  # ── io 接口 ──

  def write(self, text: str) -> int:
    if not text:
      return 0
    with self._lock:
      self._buf += text
      # 按行切割，不完整的行留缓冲等待下次 write
      while "\n" in self._buf:
        line, self._buf = self._buf.split("\n", 1)
        self._emit(line)
    return len(text)

  def flush(self) -> None:
    """刷新：将缓冲中未换行的内容也强制输出（防止进程退出时丢失）。"""
    with self._lock:
      if self._buf.strip():
        self._emit(self._buf)
        self._buf = ""
    if self._keep_stdout:
      try:
        self._original_stdout.flush()
      except Exception:
        pass

  def _emit(self, line: str) -> None:
    """
    将单行文本分发到所有目标。
    注意：此方法在 _lock 持有期间调用，不得再次获取锁。
    """
    # ① 写 system.log
    try:
      self._logger.info(line)
    except Exception:
      pass

    # ② 发送到 GUI 队列
    if self._gui_queue is not None:
      try:
        self._gui_queue.put_nowait(("print", line))
      except Exception:
        pass

    # ③ CLI 场景：保留原始终端输出
    if self._keep_stdout and self._gui_queue is None:
      try:
        self._original_stdout.write(line + "\n")
        self._original_stdout.flush()
      except Exception:
        pass

  # ── 透传其他 stdout 属性（兼容性）──

  @property
  def encoding(self):
    return getattr(self._original_stdout, "encoding", "utf-8")

  @property
  def errors(self):
    return getattr(self._original_stdout, "errors", "replace")

  def fileno(self):
    return self._original_stdout.fileno()

  def isatty(self):
    return False


# ──────────────────────────────────────────────
# 3. 公共安装函数
# ──────────────────────────────────────────────

# 全局单例：保存被替换的原始 stdout，以及当前 PrintCapture 实例
_print_capture: Optional[PrintCapture] = None


def install_print_capture(
    gui_queue: Optional[queue.Queue] = None,
    keep_stdout: bool = True,
    log_dir: str = "var/logs/llm",
) -> PrintCapture:
  """
  安装 PrintCapture，替换 sys.stdout。

  参数：
      gui_queue   : GUI 消息队列（None 表示纯 CLI 模式）
      keep_stdout : CLI 模式下是否同时保留终端输出（默认 True）
      log_dir     : 日志目录

  返回：
      PrintCapture 实例（可调用 .set_gui_queue() 动态切换模式）

  示例（CLI）：
      install_print_capture()

  示例（GUI）：
      install_print_capture(gui_queue=self.msg_queue)
  """
  global _print_capture

  logger = setup_logger(log_dir=log_dir)

  if _print_capture is None:
    # 首次安装：保存原始 stdout
    original = sys.__stdout__ or sys.stdout
    _print_capture = PrintCapture(
        logger=logger,
        original_stdout=original,
        gui_queue=gui_queue,
        keep_stdout=keep_stdout,
    )
    sys.stdout = _print_capture
  else:
    # 已安装：更新 GUI 队列即可（避免多次替换 stdout）
    _print_capture.set_gui_queue(gui_queue)

  return _print_capture


def get_print_capture() -> Optional[PrintCapture]:
  """获取当前 PrintCapture 实例（未安装时返回 None）。"""
  return _print_capture


# ──────────────────────────────────────────────
# 4. 全局单例（向后兼容，保持原有 import 不变）
# ──────────────────────────────────────────────

sys_logger = setup_logger()
trace_logger = logging.getLogger("CVA.TRACE")
