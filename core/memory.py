"""
上下文记忆模块（Memory Store）
职责：
  1. 将对话历史持久化到磁盘（JSONL），跨 session 恢复记忆
  2. 滑动窗口截断：超出 token 预算时，压缩旧消息为摘要，保留最近 N 轮
  3. 支持同一 role_name 下多 session 管理

存储结构：
  memory/{role_name}/{session_id}.jsonl   ← 完整历史（追加写）
  memory/{role_name}/sessions.json        ← session 索引（id / 创建时间 / 摘要）
"""

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional


# ─── 数据模型 ─────────────────────────────────────────────────

@dataclass
class SessionMeta:
  session_id: str
  role_name: str
  created_at: str
  updated_at: str
  message_count: int = 0
  summary: str = ""  # 人类可读的会话摘要（由 LLM 生成，可选）


# ─── 核心类 ───────────────────────────────────────────────────

class MemoryStore:
  """
  跨 session 持久化对话历史。

  关键设计：
  - 每条消息追加写入 JSONL 文件（掉电安全）
  - 加载时全量读取，在内存中维护 list
  - 滑动窗口：当消息数超过 max_messages 时，丢弃最旧的（保留 system 语境）
  - token 估算：用字符数 / 4 粗略估算（无需引入 tiktoken）
  """

  def __init__(
      self,
      memory_dir: str,
      role_name: str,
      session_id: Optional[str] = None,
      max_messages: int = 200,  # 内存中最多保留的消息轮次
      max_token_budget: int = 80000,  # 超过此估算 token 数触发压缩
  ):
    self._role_name = role_name
    self._max_messages = max_messages
    self._max_token_budget = max_token_budget

    # 目录结构
    self._role_dir = os.path.join(memory_dir, _safe_name(role_name))
    os.makedirs(self._role_dir, exist_ok=True)

    # 加载或创建 session
    if session_id:
      self._session_id = session_id
      self._messages = self._load_session(session_id)
      print(f"[Memory] ♻️  恢复 session: {session_id}（{len(self._messages)} 条历史消息）")
    else:
      import uuid
      self._session_id = str(uuid.uuid4())
      self._messages: List[Dict] = []
      print(f"[Memory] 🆕 新建 session: {self._session_id}")

    self._meta = self._load_or_create_meta()
    self._file = open(self._history_path(), "a", encoding="utf-8", buffering=1)

  # ─── 公开接口 ─────────────────────────────────────────────

  @property
  def session_id(self) -> str:
    return self._session_id

  @property
  def messages(self) -> List[Dict]:
    """当前内存中的消息列表（已经过窗口截断）"""
    return self._messages

  def append(self, message: Dict):
    """追加一条消息到内存和磁盘"""
    self._messages.append(message)
    # 持久化
    self._file.write(json.dumps(message, ensure_ascii=False) + "\n")
    self._file.flush()
    # 更新 meta
    self._meta.message_count += 1
    self._meta.updated_at = datetime.now(timezone.utc).isoformat()
    self._save_meta()
    # 检查是否需要截断
    self._maybe_trim()

  def extend(self, messages: List[Dict]):
    """批量追加"""
    for m in messages:
      self.append(m)

  def flush(self):
    """强制刷盘"""
    self._file.flush()
    os.fsync(self._file.fileno())

  def close(self):
    self.flush()
    self._file.close()

  def token_estimate(self) -> int:
    """粗略估算当前历史的 token 数（字符数 / 4）"""
    total_chars = sum(
        len(json.dumps(m, ensure_ascii=False))
        for m in self._messages
    )
    return total_chars // 4

  def summary_line(self) -> str:
    """返回单行会话摘要，用于 session 列表展示"""
    if not self._messages:
      return "（空会话）"
    first = self._messages[0]
    content = first.get("content", "")
    if isinstance(content, list):
      content = " ".join(
          b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
      )
    return str(content)[:80]

  # ─── Session 管理（静态工具方法）────────────────────────

  @classmethod
  def list_sessions(cls, memory_dir: str, role_name: str) -> List[SessionMeta]:
    """列出指定角色的所有历史 session"""
    role_dir = os.path.join(memory_dir, _safe_name(role_name))
    index_path = os.path.join(role_dir, "sessions.json")
    if not os.path.exists(index_path):
      return []
    with open(index_path, "r", encoding="utf-8") as f:
      raw = json.load(f)
    sessions = [SessionMeta(**s) for s in raw.get("sessions", [])]
    return sorted(sessions, key=lambda s: s.updated_at, reverse=True)

  @classmethod
  def delete_session(cls, memory_dir: str, role_name: str, session_id: str):
    """删除指定 session 的历史文件"""
    role_dir = os.path.join(memory_dir, _safe_name(role_name))
    hist_path = os.path.join(role_dir, f"{session_id}.jsonl")
    if os.path.exists(hist_path):
      os.remove(hist_path)
    # 从索引中移除
    index_path = os.path.join(role_dir, "sessions.json")
    if os.path.exists(index_path):
      with open(index_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
      raw["sessions"] = [s for s in raw["sessions"] if s["session_id"] != session_id]
      with open(index_path, "w", encoding="utf-8") as f:
        json.dump(raw, f, ensure_ascii=False, indent=2)

  # ─── 私有方法 ─────────────────────────────────────────────

  def _history_path(self) -> str:
    return os.path.join(self._role_dir, f"{self._session_id}.jsonl")

  def _load_session(self, session_id: str) -> List[Dict]:
    path = self._history_path()
    if not os.path.exists(path):
      print(f"[Memory] ⚠️  Session 文件不存在: {path}，从空白开始")
      return []
    messages = []
    with open(path, "r", encoding="utf-8") as f:
      for line in f:
        line = line.strip()
        if line:
          try:
            messages.append(json.loads(line))
          except json.JSONDecodeError:
            continue  # 跳过损坏行
    return messages

  def _load_or_create_meta(self) -> SessionMeta:
    index_path = os.path.join(self._role_dir, "sessions.json")
    sessions = []
    if os.path.exists(index_path):
      with open(index_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
      sessions = raw.get("sessions", [])
      for s in sessions:
        if s["session_id"] == self._session_id:
          return SessionMeta(**s)

    # 新建 meta
    now = datetime.now(timezone.utc).isoformat()
    meta = SessionMeta(
        session_id=self._session_id,
        role_name=self._role_name,
        created_at=now,
        updated_at=now,
        message_count=len(self._messages),
    )
    sessions.append(asdict(meta))
    with open(index_path, "w", encoding="utf-8") as f:
      json.dump({"sessions": sessions}, f, ensure_ascii=False, indent=2)
    return meta

  def _save_meta(self):
    index_path = os.path.join(self._role_dir, "sessions.json")
    sessions = []
    if os.path.exists(index_path):
      with open(index_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
      sessions = raw.get("sessions", [])
    # 更新或插入
    found = False
    for i, s in enumerate(sessions):
      if s["session_id"] == self._session_id:
        sessions[i] = asdict(self._meta)
        found = True
        break
    if not found:
      sessions.append(asdict(self._meta))
    with open(index_path, "w", encoding="utf-8") as f:
      json.dump({"sessions": sessions}, f, ensure_ascii=False, indent=2)

  def _maybe_trim(self):
    """
    滑动窗口截断策略：
    - 消息数 > max_messages：丢弃最旧的 25%（保留整轮对话完整性）
    - token 估算 > max_token_budget：同上触发
    只截断内存中的列表，磁盘文件保留完整历史（用于审计）。
    """
    needs_trim = (
        len(self._messages) > self._max_messages
        or self.token_estimate() > self._max_token_budget
    )
    if not needs_trim:
      return

    # 计算要保留的起始位置（丢弃最旧的 25%）
    drop_count = max(1, len(self._messages) // 4)

    # 确保从完整的"用户消息"边界截断，不截断在 tool_result 中间
    start = drop_count
    while start < len(self._messages):
      if self._messages[start].get("role") == "user":
        # 检查不是 tool_result 消息
        content = self._messages[start].get("content", "")
        if not isinstance(content, list) or not any(
            isinstance(b, dict) and b.get("type") == "tool_result"
            for b in content
        ):
          break
      start += 1

    trimmed = len(self._messages) - start
    self._messages = self._messages[start:]
    print(f"[Memory] ✂️  上下文窗口截断：移除最旧 {trimmed} 条，保留 {len(self._messages)} 条")


# ─── 工具函数 ─────────────────────────────────────────────────

def _safe_name(name: str) -> str:
  """将角色名转换为安全的目录名"""
  return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
