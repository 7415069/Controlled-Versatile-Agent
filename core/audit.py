"""
审计日志（Audit Log）— 结构化 JSONL，追加写入，按日滚动
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict


class AuditLogger:
    """
    线程安全的审计日志写入器。
    每行一个 JSON 对象（JSONL 格式），文件按日期滚动。
    """

    def __init__(self, log_dir: str, instance_id: str, role_name: str):
        self._log_dir = log_dir
        self._instance_id = instance_id
        self._role_name = role_name
        self._lock = threading.Lock()
        os.makedirs(log_dir, exist_ok=True)

    def log(self, event_type: str, payload: Dict[str, Any] = None):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "instance_id": self._instance_id,
            "role_name": self._role_name,
            "event_type": event_type,
            **(payload or {}),
        }
        log_path = self._current_log_path()
        with self._lock:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _current_log_path(self) -> str:
        date_str = datetime.now().strftime("%Y-%m-%d")
        filename = f"cva-audit-{self._instance_id[:8]}-{date_str}.jsonl"
        return os.path.join(self._log_dir, filename)
