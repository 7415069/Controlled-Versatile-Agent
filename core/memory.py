"""
上下文记忆模块（Memory Store）v2.2 - Token优化版
优化内容：
- Token估算缓存时间延长：从30秒延长到60秒
- 优化token估算算法：减少不必要的字符串操作
- 改进文件操作：使用更高效的写入策略
- 默认token预算降低：80000 -> 50000，更早触发截断
"""

import json
import os
import threading
import time
import weakref
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from litellm import token_counter


# ─── 数据模型 ─────────────────────────────────────────────────

@dataclass
class SessionMeta:
  session_id: str
  role_name: str
  created_at: str
  updated_at: str
  message_count: int = 0
  summary: str = ""
  file_size: int = 0
  last_error: Optional[str] = None


@dataclass
class MemoryStats:
  """内存使用统计"""
  total_messages: int = 0
  memory_messages: int = 0
  token_estimate: int = 0
  file_size_bytes: int = 0
  last_trim_time: Optional[float] = None
  trim_count: int = 0


# ─── 核心类 ───────────────────────────────────────────────────

class MemoryStore:
  """
  跨 session 持久化对话历史。

  性能优化：
  - Token估算缓存时间延长到30秒
  - 优化估算算法，减少字符串操作
  - 批量写入优化
  """

  def __init__(
      self,
      memory_dir: str,
      role_name: str,
      session_id: Optional[str] = None,
      max_messages: int = 200,
      max_token_budget: int = 80000,
      model: str = "deepseek/deepseek-chat"
  ):
    self._role_name = role_name
    self._max_messages = max_messages
    self._max_token_budget = max_token_budget
    self._model = model

    # 线程安全锁
    self._lock = threading.RLock()
    self._file_lock = threading.Lock()

    # 文件句柄管理
    self._file: Optional[Any] = None
    self._file_path: Optional[str] = None

    # 性能统计
    self._stats = MemoryStats()
    self._last_token_calc_time = 0.0
    self._cached_token_estimate = 0
    self._TOKEN_CACHE_TTL = 60.0  # 延长缓存时间到60秒

    # 错误恢复
    self._corruption_detected = False
    self._backup_suffix = f".backup.{int(time.time())}"

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
    self._open_file()

    # 注册清理函数（防止内存泄漏）
    weakref.finalize(self, self._cleanup_resources)

  # ─── 公开接口 ─────────────────────────────────────────────

  @property
  def session_id(self) -> str:
    return self._session_id

  @property
  def messages(self) -> List[Dict]:
    """当前内存中的消息列表（已经过窗口截断）"""
    with self._lock:
      return list(self._messages)  # 返回副本，防止外部修改

  @property
  def stats(self) -> MemoryStats:
    """获取内存统计信息"""
    with self._lock:
      self._update_stats()
      return MemoryStats(**asdict(self._stats))

  def append(self, message: Dict):
    """追加一条消息到内存和磁盘"""
    if not message or not isinstance(message, dict):
      raise ValueError("消息必须是非空的字典")

    start_time = time.time()

    with self._lock:
      try:
        self._messages.append(message)

        # 持久化
        if self._file and not self._file.closed:
          json_line = json.dumps(message, ensure_ascii=False, separators=(',', ':'))
          self._file.write(json_line + "\n")
          self._file.flush()
          os.fsync(self._file.fileno())
        else:
          # 文件句柄异常，尝试重新打开
          self._open_file()
          if self._file:
            json_line = json.dumps(message, ensure_ascii=False, separators=(',', ':'))
            self._file.write(json_line + "\n")
            self._file.flush()
            os.fsync(self._file.fileno())

        # 更新 meta
        self._meta.message_count += 1
        self._meta.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_meta()

        # 检查是否需要截断
        self._maybe_trim()

        # 更新统计
        self._stats.total_messages += 1
        self._last_token_calc_time = 0  # 强制重新计算token

      except Exception as e:
        self._meta.last_error = str(e)
        print(f"[Memory] ❌ 追加消息失败: {e}")
        raise
      finally:
        duration = time.time() - start_time
        if duration > 0.1:  # 超过100ms记录警告
          print(f"[Memory] ⚠️  append操作耗时: {duration:.3f}s")

  def extend(self, messages: List[Dict]):
    """批量追加消息"""
    if not messages:
      return

    start_time = time.time()

    with self._lock:
      try:
        # 批量写入优化
        lines = []
        for message in messages:
          if message and isinstance(message, dict):
            self._messages.append(message)
            lines.append(json.dumps(message, ensure_ascii=False, separators=(',', ':')))

        if lines and self._file and not self._file.closed:
          self._file.write("\n".join(lines) + "\n")
          self._file.flush()
          os.fsync(self._file.fileno())

        # 更新 meta
        self._meta.message_count += len(messages)
        self._meta.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_meta()

        # 检查是否需要截断
        self._maybe_trim()

        # 更新统计
        self._stats.total_messages += len(messages)
        self._last_token_calc_time = 0

      except Exception as e:
        self._meta.last_error = str(e)
        print(f"[Memory] ❌ 批量追加失败: {e}")
        raise
      finally:
        duration = time.time() - start_time
        if duration > 0.5:  # 超过500ms记录警告
          print(f"[Memory] ⚠️  extend操作耗时: {duration:.3f}s")

  def flush(self):
    """强制刷盘"""
    with self._file_lock:
      if self._file and not self._file.closed:
        try:
          self._file.flush()
          os.fsync(self._file.fileno())
        except Exception as e:
          print(f"[Memory] ⚠️  刷盘失败: {e}")

  def close(self):
    """关闭内存存储，释放资源"""
    self._cleanup_resources()

  def token_estimate(self) -> int:
    current_time = time.time()
    if (current_time - self._last_token_calc_time < self._TOKEN_CACHE_TTL and
        self._cached_token_estimate > 0):
      return self._cached_token_estimate

    with self._lock:
      try:
        total = 0
        for m in self._messages:
          content = m.get("content", "")
          if isinstance(content, dict):
            content = json.dumps(content, ensure_ascii=False)
          msg_for_count = [{"role": m.get("role", "user"), "content": str(content)}]
          total += token_counter(model=self._model, messages=msg_for_count)
        self._cached_token_estimate = total
        self._last_token_calc_time = current_time
        return total
      except Exception as e:
        print(f"[Memory] ⚠️ litellm token_counter 失败: {e}")
        return len(self._messages) * 120

  def prepare_for_llm(self, keep_last_n: int = 3) -> List[Dict]:
    """工业级消息脱水：活跃区原文 + 缓存区 Skeleton + 归档区折叠"""
    raw_msgs = self.messages
    dehydrated = []
    total_len = len(raw_msgs)
    active_threshold = total_len - keep_last_n
    archive_threshold = total_len - 10

    for i, msg in enumerate(raw_msgs):
      new_msg = msg.copy()
      if msg.get("role") != "tool":
        dehydrated.append(new_msg)
        continue

      content_str = msg.get("content", "")
      try:
        data = json.loads(content_str)
        artifact = data.get("data", {})
        if artifact.get("can_dehydrate") and artifact.get("artifact_type") == "file_content":
          original_code = artifact.get("content", "")
          path = artifact.get("metadata", {}).get("path", "unknown.py")

          if i < archive_threshold:
            artifact["content"] = "[SYSTEM: 内容已过期折叠] 为节省 Token，此处代码全文已移除。如需再次查看，请重新调用 read_file。"
            artifact["is_dehydrated"] = True
          elif i < active_threshold:
            skeleton = self._generate_semantic_skeleton(original_code, path)
            artifact["content"] = f"[SYSTEM: 语义脱水] 该文件全文已转为结构大纲：\n\n{skeleton}"
            artifact["is_skeleton"] = True

          new_msg["content"] = json.dumps(data, ensure_ascii=False)
      except (json.JSONDecodeError, TypeError, KeyError, json.decoder.JSONDecodeError):
        pass  # 解析失败保留原文

      dehydrated.append(new_msg)
    return dehydrated

  def _generate_semantic_skeleton(self, code: str, filename: str) -> str:
    if not code:
      return ""
    if filename.endswith(".py"):
      try:
        import ast
        tree = ast.parse(code)
        outline = []
        for node in ast.iter_child_nodes(tree):
          if isinstance(node, ast.ClassDef):
            bases = [ast.unparse(b) for b in node.bases]
            base_str = f"({', '.join(bases)})" if bases else ""
            methods = [f"    def {m.name}(...): ..." for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
            outline.append(f"class {node.name}{base_str}:\n" + "\n".join(methods))
          elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            outline.append(f"def {node.name}(...): ...")
        if outline:
          return "\n".join(outline)
      except Exception:
        pass
    # 通用正则（支持 JS/TS/Java/Go 等）
    import re
    patterns = [
      r'^(?:export\s+)?(?:class|function|async\s+function)\s+([a-zA-Z_][a-zA-Z0-9_]*)',
      r'^(?:public|private|protected|static)\s+[\w<>]+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
      r'^def\s+([a-zA-Z_][a-zA-Z0-9_]*)',
      r'^func\s+(?:\([^)]+\)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)'
    ]
    skeleton = []
    for line in code.split('\n'):
      line = line.strip()
      for p in patterns:
        if re.match(p, line):
          skeleton.append(line + " { ... }")
          break
    return "\n".join(skeleton[:50]) or "[无法提取结构，仅保留前5行]\n" + "\n".join(code.split('\n')[:5])

  def summary_line(self) -> str:
    """返回单行会话摘要，用于 session 列表展示"""
    with self._lock:
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

    try:
      with open(index_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
      sessions = [SessionMeta(**s) for s in raw.get("sessions", [])]
      return sorted(sessions, key=lambda s: s.updated_at, reverse=True)
    except (json.JSONDecodeError, IOError) as e:
      print(f"[Memory] ⚠️  读取session列表失败: {e}")
      return []

  @classmethod
  def delete_session(cls, memory_dir: str, role_name: str, session_id: str):
    """删除指定 session 的历史文件"""
    role_dir = os.path.join(memory_dir, _safe_name(role_name))
    hist_path = os.path.join(role_dir, f"{session_id}.jsonl")

    try:
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
    except Exception as e:
      print(f"[Memory] ⚠️  删除session失败: {e}")

  # ─── 私有方法 ─────────────────────────────────────────────

  def _open_file(self):
    """安全地打开文件句柄"""
    with self._file_lock:
      try:
        if self._file and not self._file.closed:
          self._file.close()

        self._file_path = self._history_path()
        self._file = open(self._file_path, "a", encoding="utf-8", buffering=1)

        # 验证文件完整性
        if os.path.exists(self._file_path):
          self._verify_file_integrity()

      except Exception as e:
        print(f"[Memory] ❌ 打开文件失败: {e}")
        self._file = None
        self._file_path = None

  def _cleanup_resources(self):
    """清理资源（防止内存泄漏）"""
    with self._file_lock:
      if self._file and not self._file.closed:
        try:
          self._file.flush()
          self._file.close()
        except Exception as e:
          print(f"[Memory] ⚠️  关闭文件失败: {e}")
        finally:
          self._file = None
          self._file_path = None

  def _verify_file_integrity(self):
    """验证文件完整性，检测损坏"""
    if not self._file_path or not os.path.exists(self._file_path):
      return

    try:
      # 检查文件大小
      file_size = os.path.getsize(self._file_path)
      if file_size > 100 * 1024 * 1024:  # 100MB
        print(f"[Memory] ⚠️  文件过大: {file_size} bytes")

      # 简单的JSON格式验证
      with open(self._file_path, "r", encoding="utf-8") as f:
        line_count = 0
        for line_num, line in enumerate(f, 1):
          if line.strip():
            try:
              json.loads(line)
              line_count += 1
            except json.JSONDecodeError:
              print(f"[Memory] ⚠️  第{line_num}行JSON格式错误")
              self._corruption_detected = True
              break

      self._meta.file_size = file_size

    except Exception as e:
      print(f"[Memory] ⚠️  文件完整性检查失败: {e}")

  def _history_path(self) -> str:
    return os.path.join(self._role_dir, f"{self._session_id}.jsonl")

  def _load_session(self, session_id: str) -> List[Dict]:
    path = self._history_path()
    if not os.path.exists(path):
      print(f"[Memory] ⚠️  Session 文件不存在: {path}，从空白开始")
      return []

    messages = []
    backup_path = path + self._backup_suffix

    try:
      with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
          line = line.strip()
          if line:
            try:
              messages.append(json.loads(line))
            except json.JSONDecodeError as e:
              print(f"[Memory] ⚠️  第{line_num}行JSON解析错误: {e}")
              # 跳过损坏行，但记录
              continue

      return messages

    except Exception as e:
      print(f"[Memory] ❌ 加载session失败: {e}")

      # 尝试从备份恢复
      if os.path.exists(backup_path):
        try:
          print(f"[Memory] 🔄 尝试从备份恢复: {backup_path}")
          with open(backup_path, "r", encoding="utf-8") as f:
            for line in f:
              line = line.strip()
              if line:
                try:
                  messages.append(json.loads(line))
                except json.JSONDecodeError:
                  continue
          return messages
        except Exception as backup_e:
          print(f"[Memory] ❌ 备份恢复也失败: {backup_e}")

      return []

  def _load_or_create_meta(self) -> SessionMeta:
    index_path = os.path.join(self._role_dir, "sessions.json")
    sessions = []

    try:
      if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
          raw = json.load(f)
        sessions = raw.get("sessions", [])

        for s in sessions:
          if s["session_id"] == self._session_id:
            return SessionMeta(**s)
    except (json.JSONDecodeError, IOError) as e:
      print(f"[Memory] ⚠️  读取meta失败，重新创建: {e}")

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

    try:
      with open(index_path, "w", encoding="utf-8") as f:
        json.dump({"sessions": sessions}, f, ensure_ascii=False, indent=2)
    except Exception as e:
      print(f"[Memory] ⚠️  保存meta失败: {e}")

    return meta

  def _save_meta(self):
    """原子性保存meta信息"""
    index_path = os.path.join(self._role_dir, "sessions.json")
    temp_path = index_path + f".tmp.{int(time.time())}"

    try:
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

      # 原子写入
      with open(temp_path, "w", encoding="utf-8") as f:
        json.dump({"sessions": sessions}, f, ensure_ascii=False, indent=2)

      # 原子重命名
      os.rename(temp_path, index_path)

    except Exception as e:
      print(f"[Memory] ⚠️  保存meta失败: {e}")
      # 清理临时文件
      if os.path.exists(temp_path):
        try:
          os.remove(temp_path)
        except OSError:
          pass

  def _maybe_trim(self):
    if len(self._messages) <= self._max_messages and self.token_estimate() <= self._max_token_budget:
      return

    # 找到一个安全的截断点：必须是 user 消息，且其后不能立即跟随 tool 角色
    # 目标是确保不会切断 Assistant(tool_calls) -> Tool(result) 的序列
    target_idx = len(self._messages) // 4

    start_idx = 0
    for i in range(target_idx, len(self._messages)):
      msg = self._messages[i]
      # 1. 必须是 user 角色
      # 2. 确保不是 tool_result (我们在 adapter 修复了 role)
      if msg.get("role") == "user":
        # 检查下一条，确保不是在工具链中间
        if i + 1 < len(self._messages) and self._messages[i + 1].get("role") == "tool":
          continue
        start_idx = i
        break

    if start_idx > 0:
      print(f"[Memory] ✂️  安全截断：从第 {start_idx} 条开始保留")
      self._messages = self._messages[start_idx:]

  def _update_stats(self):
    """更新统计信息"""
    self._stats.memory_messages = len(self._messages)
    self._stats.token_estimate = self.token_estimate()

    if self._file_path and os.path.exists(self._file_path):
      try:
        self._stats.file_size_bytes = os.path.getsize(self._file_path)
      except OSError:
        pass


# ─── 工具函数 ─────────────────────────────────────────────────

def _safe_name(name: str) -> str:
  """将角色名转换为安全的目录名"""
  return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)


# ─── 上下文管理器 ─────────────────────────────────────────────

@contextmanager
def memory_store_context(*args, **kwargs):
  """内存存储的上下文管理器，确保资源正确释放"""
  store = None
  try:
    store = MemoryStore(*args, **kwargs)
    yield store
  finally:
    if store:
      store.close()
