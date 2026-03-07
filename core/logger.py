# core/logger.py
import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logger(log_dir="var/logs/llm", level=logging.INFO):
  os.makedirs(log_dir, exist_ok=True)

  # 获取根日志记录器
  logger = logging.getLogger("CVA")
  logger.setLevel(logging.INFO)  # 允许所有级别，由 handler 过滤

  # 防止重复添加 handler
  if logger.handlers:
    return logger

  formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

  # 1. 控制台 Handler - 简洁输出
  console_handler = logging.StreamHandler()
  console_handler.setLevel(level)
  console_handler.setFormatter(formatter)

  # 2. 系统运行日志 - 详细记录
  system_file = os.path.join(log_dir, "system.log")
  file_handler = RotatingFileHandler(system_file, maxBytes=10 * 1024 * 1024, backupCount=5)
  file_handler.setLevel(logging.INFO)
  file_handler.setFormatter(formatter)

  # 3. LLM 原始载荷日志 (Trace 专用)
  trace_file = os.path.join(log_dir, "llm_trace.log")
  trace_handler = RotatingFileHandler(trace_file, maxBytes=20 * 1024 * 1024, backupCount=5)
  trace_handler.setLevel(logging.INFO)  # 我们把 Trace 映射到 DEBUG
  trace_handler.setFormatter(formatter)

  # 为不同模块设置过滤（可选）
  logger.addHandler(console_handler)
  logger.addHandler(file_handler)

  # 创建一个专门用于记录 LLM Payload 的 Logger
  trace_logger = logging.getLogger("CVA.TRACE")
  trace_logger.propagate = False  # 不向上级传递，避免重复记录
  trace_logger.addHandler(trace_handler)
  trace_logger.addHandler(console_handler if level == logging.DEBUG else logging.NullHandler())

  return logger


# 全局单例初始化
sys_logger = setup_logger()
trace_logger = logging.getLogger("CVA.TRACE")
