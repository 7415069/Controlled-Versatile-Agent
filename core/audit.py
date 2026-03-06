"""
审计日志（Audit Log）v2 - 结构化 JSONL，追加写入，按日滚动 + 日志轮转
"""

import json
import os
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict


class AuditLogger:
  """
  线程安全的审计日志写入器。
  每行一个 JSON 对象（JSONL 格式），文件按日期滚动。
  
  新增功能：
  - 日志文件大小限制和轮转
  - 自动清理过期日志
  - 日志压缩支持
  """

  def __init__(
      self,
      log_dir: str,
      instance_id: str,
      role_name: str,
      max_file_size: int = 100 * 1024 * 1024,  # 100MB
      max_log_age_days: int = 30,  # 保留30天
      enable_compression: bool = False
  ):
    self._log_dir = log_dir
    self._instance_id = instance_id
    self._role_name = role_name
    self._lock = threading.Lock()
    self._max_file_size = max_file_size
    self._max_log_age_days = max_log_age_days
    self._enable_compression = enable_compression

    os.makedirs(log_dir, exist_ok=True)

    # 启动时清理过期日志
    self._cleanup_old_logs()

  def log(self, event_type: str, payload: Dict[str, Any] = None):
    """记录审计日志"""
    record = {
      "timestamp": datetime.now(timezone.utc).isoformat(),
      "instance_id": self._instance_id,
      "role_name": self._role_name,
      "event_type": event_type,
      **(payload or {}),
    }

    log_path = self._current_log_path()

    with self._lock:
      # 检查文件大小，如果超过限制则轮转
      if os.path.exists(log_path):
        file_size = os.path.getsize(log_path)
        if file_size >= self._max_file_size:
          self._rotate_log(log_path)
          log_path = self._current_log_path()

      # 追加写入日志
      with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

  def _current_log_path(self) -> str:
    """获取当前日志文件路径"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"cva-audit-{self._instance_id[:8]}-{date_str}.jsonl"
    return os.path.join(self._log_dir, filename)

  def _rotate_log(self, log_path: str):
    """轮转日志文件"""
    try:
      base_path = log_path.rsplit('.', 1)[0]  # 移除扩展名
      timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

      # 重命名旧日志文件
      rotated_path = f"{base_path}_{timestamp}.jsonl"
      os.rename(log_path, rotated_path)

      # 可选：压缩旧日志
      if self._enable_compression:
        self._compress_log(rotated_path)

    except Exception as e:
      # 轮转失败不应影响日志记录
      print(f"[AuditLogger] ⚠️  日志轮转失败: {e}")

  def _compress_log(self, log_path: str):
    """压缩日志文件（使用gzip）"""
    try:
      import gzip
      import shutil

      compressed_path = log_path + ".gz"
      with open(log_path, 'rb') as f_in:
        with gzip.open(compressed_path, 'wb') as f_out:
          shutil.copyfileobj(f_in, f_out)

      # 删除原始文件
      os.remove(log_path)

    except ImportError:
      # gzip 不可用，跳过压缩
      pass
    except Exception as e:
      print(f"[AuditLogger] ⚠️  日志压缩失败: {e}")

  def _cleanup_old_logs(self):
    """清理过期的日志文件"""
    try:
      now = datetime.now()
      cutoff_date = now - timedelta(days=self._max_log_age_days)

      for filename in os.listdir(self._log_dir):
        filepath = os.path.join(self._log_dir, filename)

        # 只处理审计日志文件
        if not filename.startswith("cva-audit-"):
          continue

        # 获取文件修改时间
        file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))

        # 删除过期文件
        if file_mtime < cutoff_date:
          try:
            os.remove(filepath)
            print(f"[AuditLogger] 🗑️  清理过期日志: {filename}")
          except OSError as e:
            print(f"[AuditLogger] ⚠️  删除日志失败 {filename}: {e}")

    except Exception as e:
      print(f"[AuditLogger] ⚠️  清理日志失败: {e}")

  def get_log_stats(self) -> Dict[str, Any]:
    """获取日志统计信息"""
    try:
      total_files = 0
      total_size = 0
      oldest_log = None
      newest_log = None

      for filename in os.listdir(self._log_dir):
        if not filename.startswith("cva-audit-"):
          continue

        filepath = os.path.join(self._log_dir, filename)
        total_files += 1
        total_size += os.path.getsize(filepath)

        file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
        if oldest_log is None or file_mtime < oldest_log:
          oldest_log = file_mtime
        if newest_log is None or file_mtime > newest_log:
          newest_log = file_mtime

      return {
        "total_files": total_files,
        "total_size_bytes": total_size,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "oldest_log": oldest_log.isoformat() if oldest_log else None,
        "newest_log": newest_log.isoformat() if newest_log else None,
      }

    except Exception as e:
      return {"error": str(e)}
