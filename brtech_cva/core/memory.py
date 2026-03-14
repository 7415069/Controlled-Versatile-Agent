"""
上下文记忆模块（Memory Store）v2.3 - 并发安全修复版

修复内容：
  P0-1: append() 持有 _lock 期间调用 os.fsync() 导致死锁
        → 将 I/O 操作（fsync、_save_meta）移至 _lock 释放后执行
  P1-2: flush() 与 append() 使用不同的锁（_file_lock vs _lock）产生竞态
        → 统一删除 _file_lock，所有文件操作归 _lock 管辖
  P2-3: TaskState.discovered_knowledge 无上限，长期运行后 token 膨胀
        → add_knowledge() 增加 LRU 上限（默认 50 条），超出时淘汰最旧的键
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

from brtech_cva.core.config import cva_settings

# ─── 常量 ─────────────────────────────────────────────────────

_KNOWLEDGE_MAX_ENTRIES = 50  # TaskState 知识库最大条目数


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
  total_messages: int = 0
  memory_messages: int = 0
  token_estimate: int = 0
  file_size_bytes: int = 0
  last_trim_time: Optional[float] = None
  trim_count: int = 0


@dataclass
class TaskState:
  """
  结构化任务状态机（Active State Machine）。
  是 Agent 的「工作记忆」，每轮注入 System Prompt，零 LLM 调用维护。
  """
  current_goal: str = ""
  plan: List[str] = None
  completed_steps: List[str] = None
  active_step: str = ""
  discovered_knowledge: Dict[str, str] = None
  pending_risks: List[str] = None
  iteration_at_plan: int = 0

  def __post_init__(self):
    if self.plan is None:
      self.plan = []
    if self.completed_steps is None:
      self.completed_steps = []
    if self.discovered_knowledge is None:
      self.discovered_knowledge = {}
    if self.pending_risks is None:
      self.pending_risks = []

  def update_from_plan(self, goal: str, milestones: List[str], iteration: int):
    self.current_goal = goal
    self.plan = milestones
    self.active_step = milestones[0] if milestones else ""
    self.iteration_at_plan = iteration
    self.completed_steps = []

  def mark_step_done(self, step_description: str):
    if self.active_step and self.active_step not in self.completed_steps:
      self.completed_steps.append(self.active_step)
    for step in self.plan:
      if step not in self.completed_steps:
        self.active_step = step
        return
    self.active_step = ""

  def add_knowledge(self, key: str, value: str):
    """
    记录发现的关键事实。

    修复 P2-3：加入 LRU 上限。当条目数超过 _KNOWLEDGE_MAX_ENTRIES 时，
    淘汰最早插入的键，防止 System Prompt 因知识库无限增长而膨胀。
    """
    # 若 key 已存在，先删除以刷新插入顺序（Python 3.7+ dict 保持插入序）
    self.discovered_knowledge.pop(key, None)
    self.discovered_knowledge[key] = value

    # 超出上限时删除最旧的条目
    while len(self.discovered_knowledge) > _KNOWLEDGE_MAX_ENTRIES:
      oldest_key = next(iter(self.discovered_knowledge))
      del self.discovered_knowledge[oldest_key]

  def add_risk(self, risk: str):
    if risk not in self.pending_risks:
      self.pending_risks.append(risk)

  def to_prompt_block(self) -> str:
    if not self.current_goal:
      return ""

    lines = [
      "---",
      "### 📋 当前任务状态 (TaskState)",
      f"**目标**: {self.current_goal}",
    ]

    if self.plan:
      plan_lines = []
      for step in self.plan:
        if step in self.completed_steps:
          plan_lines.append(f"  - [x] {step}")
        elif step == self.active_step:
          plan_lines.append(f"  - [→] **{step}** ← 当前步骤")
        else:
          plan_lines.append(f"  - [ ] {step}")
      lines.append("**计划**:\n" + "\n".join(plan_lines))

    if self.discovered_knowledge:
      kv = "; ".join(f"{k}: {v}" for k, v in list(self.discovered_knowledge.items())[-5:])
      lines.append(f"**已知事实**: {kv}")

    if self.pending_risks:
      lines.append(f"**待处理风险**: {'; '.join(self.pending_risks[-3:])}")

    progress = f"{len(self.completed_steps)}/{len(self.plan)}"
    lines.append(f"**进度**: {progress} 步骤完成")
    lines.append("---")
    return "\n".join(lines)


# ─── 核心类 ───────────────────────────────────────────────────

class MemoryStore:
  """
  跨 session 持久化对话历史。

  并发安全说明：
    - 统一使用单把 _lock（RLock）保护所有内存状态和文件操作。
    - 去除了原来的 _file_lock，避免双锁导致的竞态条件。
    - append() 的 fsync / _save_meta 在释放 _lock 后执行，消除持锁期间阻塞。
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
    self._max_messages = max_messages or cva_settings.memory_settings.default_max_messages
    self._max_token_budget = max_token_budget or cva_settings.memory_settings.default_token_budget
    self._model = model

    # 修复 P1-2：只保留一把锁，消除双锁竞态
    self._lock = threading.RLock()

    # 文件句柄
    self._file: Optional[Any] = None
    self._file_path: Optional[str] = None

    # 性能统计
    self._stats = MemoryStats()
    self._last_token_calc_time = 0.0
    self._cached_token_estimate = 0
    self._TOKEN_CACHE_TTL = cva_settings.memory_settings.token_cache_ttl

    # 错误恢复
    self._corruption_detected = False
    self._backup_suffix = f".backup.{int(time.time())}"

    # 目录结构
    self._role_dir = os.path.join(memory_dir, _safe_name(role_name))
    os.makedirs(self._role_dir, exist_ok=True)

    # TaskState 状态机
    self._task_state = TaskState()

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

    weakref.finalize(self, self._cleanup_resources)

  # ─── 公开接口 ─────────────────────────────────────────────

  @property
  def session_id(self) -> str:
    return self._session_id

  @property
  def messages(self) -> List[Dict]:
    with self._lock:
      return list(self._messages)

  @property
  def stats(self) -> MemoryStats:
    with self._lock:
      self._update_stats()
      return MemoryStats(**asdict(self._stats))

  def get_current_state(self) -> TaskState:
    return self._task_state

  def update_task_state(self, goal: str, milestones: List[str], iteration: int):
    self._task_state.update_from_plan(goal, milestones, iteration)

  def append(self, message: Dict):
    """
    追加一条消息到内存和磁盘。

    修复 P0-1：fsync 和 _save_meta 移至 _lock 释放后执行。
      原来的实现在持有 _lock 期间调用 os.fsync()，
      fsync 可能阻塞数秒，导致所有争抢 _lock 的线程（如 token_estimate）假死。
    """
    if not message or not isinstance(message, dict):
      raise ValueError("消息必须是非空的字典")

    start_time = time.time()
    json_line = None
    need_save_meta = False

    with self._lock:
      try:
        tagged_message = self._tag_importance(message)
        self._messages.append(tagged_message)

        # 在锁内完成序列化和内存写入
        json_line = json.dumps(tagged_message, ensure_ascii=False, separators=(',', ':'))

        if self._file and not self._file.closed:
          self._file.write(json_line + "\n")
          # 不在锁内调用 fsync，仅 flush 到 OS 缓冲区
          self._file.flush()
        else:
          self._open_file()
          if self._file:
            self._file.write(json_line + "\n")
            self._file.flush()

        self._meta.message_count += 1
        self._meta.updated_at = datetime.now(timezone.utc).isoformat()
        need_save_meta = True

        # 增量 token 计数
        delta = self._count_tokens_single(tagged_message)
        self._cached_token_estimate += delta
        self._last_token_calc_time = time.time()

        self._maybe_trim()
        self._stats.total_messages += 1

      except Exception as e:
        self._meta.last_error = str(e)
        print(f"[Memory] ❌ 追加消息失败: {e}")
        raise

    # ── 锁外执行耗时 I/O（修复 P0-1 关键改动）──
    if need_save_meta:
      try:
        self._save_meta()
      except Exception as e:
        print(f"[Memory] ⚠️  保存meta失败: {e}")

    # fsync 在锁外执行，即使阻塞也不会影响其他线程
    try:
      if self._file and not self._file.closed:
        os.fsync(self._file.fileno())
    except OSError:
      pass

    duration = time.time() - start_time
    if duration > 0.1:
      print(f"[Memory] ⚠️  append操作耗时: {duration:.3f}s")

  def extend(self, messages: List[Dict]):
    """批量追加消息"""
    if not messages:
      return

    start_time = time.time()
    need_save_meta = False

    with self._lock:
      try:
        lines = []
        for message in messages:
          if message and isinstance(message, dict):
            self._messages.append(message)
            lines.append(json.dumps(message, ensure_ascii=False, separators=(',', ':')))

        if lines and self._file and not self._file.closed:
          self._file.write("\n".join(lines) + "\n")
          self._file.flush()

        self._meta.message_count += len(messages)
        self._meta.updated_at = datetime.now(timezone.utc).isoformat()
        need_save_meta = True

        self._maybe_trim()
        self._stats.total_messages += len(messages)
        self._last_token_calc_time = 0

      except Exception as e:
        self._meta.last_error = str(e)
        print(f"[Memory] ❌ 批量追加失败: {e}")
        raise

    # 锁外 I/O
    if need_save_meta:
      try:
        self._save_meta()
      except Exception as e:
        print(f"[Memory] ⚠️  保存meta失败: {e}")

    try:
      if self._file and not self._file.closed:
        os.fsync(self._file.fileno())
    except OSError:
      pass

    duration = time.time() - start_time
    if duration > 0.5:
      print(f"[Memory] ⚠️  extend操作耗时: {duration:.3f}s")

  def flush(self):
    """强制刷盘（修复 P1-2：统一使用 _lock，删除 _file_lock）"""
    with self._lock:
      if self._file and not self._file.closed:
        try:
          self._file.flush()
        except Exception as e:
          print(f"[Memory] ⚠️  flush失败: {e}")
    # fsync 在锁外执行
    try:
      if self._file and not self._file.closed:
        os.fsync(self._file.fileno())
    except OSError:
      pass

  def close(self):
    self._cleanup_resources()

  def token_estimate(self) -> int:
    current_time = time.time()
    if (current_time - self._last_token_calc_time < self._TOKEN_CACHE_TTL and
        self._cached_token_estimate > 0):
      return self._cached_token_estimate

    with self._lock:
      try:
        total = sum(self._count_tokens_single(m) for m in self._messages)
        self._cached_token_estimate = total
        self._last_token_calc_time = current_time
        return total
      except Exception as e:
        print(f"[Memory] ⚠️ token_counter 失败: {e}")
        return len(self._messages) * 120

  def _count_tokens_single(self, message: Dict) -> int:
    try:
      content = message.get("content", "")
      if isinstance(content, (dict, list)):
        content = json.dumps(content, ensure_ascii=False)
      msg_for_count = [{"role": message.get("role", "user"), "content": str(content)}]
      return token_counter(model=self._model, messages=msg_for_count)
    except Exception:
      content_str = str(message.get("content", ""))
      return max(4, len(content_str) // 3)

  def prepare_for_llm(self, keep_last_n: int = 3) -> List[Dict]:
    """
    增强版消息脱水：按重要性标签过滤 + 图片去重 [MODIFIED]
    保留了原有的 ANCHOR/DECISION/PROCESS/NOISE 逻辑和代码骨架提取。
    """
    raw_msgs = self.messages
    total_len = len(raw_msgs)
    active_boundary = total_len - (keep_last_n * 3)
    result = []

    tool_call_owner: Dict[str, int] = {}
    for i, msg in enumerate(raw_msgs):
      if msg.get("role") == "assistant":
        for tc in msg.get("tool_calls", []):
          if isinstance(tc, dict):
            tc_id = tc.get("id", "")
            if tc_id:
              tool_call_owner[tc_id] = i

    skip_indices = set()
    for i, msg in enumerate(raw_msgs):
      tag = msg.get("_importance", "PROCESS")
      role = msg.get("role", "")
      if tag == "NOISE":
        skip_indices.add(i)
        if role == "tool":
          tc_id = msg.get("tool_call_id", "")
          if tc_id and tc_id in tool_call_owner:
            skip_indices.add(tool_call_owner[tc_id])
        if role == "assistant":
          for tc in msg.get("tool_calls", []):
            if isinstance(tc, dict):
              tc_id = tc.get("id", "")
              for j, other in enumerate(raw_msgs):
                if other.get("role") == "tool" and other.get("tool_call_id") == tc_id:
                  skip_indices.add(j)

    last_image_idx = -1
    for i in range(total_len - 1, -1, -1):
      if '"artifact_type": "image"' in str(raw_msgs[i].get("content", "")):
        last_image_idx = i
        break

    for i, msg in enumerate(raw_msgs):
      tag = msg.get("_importance", "PROCESS")
      role = msg.get("role", "")

      if tag == "ANCHOR":
        clean = {k: v for k, v in msg.items() if not k.startswith("_")}
        result.append(clean)
        continue

      if i in skip_indices:
        continue

      if role == "tool":
        clean = {k: v for k, v in msg.items() if not k.startswith("_")}
        content_str = clean.get("content", "")

        try:
          data = json.loads(content_str)
          artifact = data.get("data", {})

          if artifact.get("can_dehydrate") and artifact.get("artifact_type") == "file_content":
            if i < active_boundary:
              artifact["content"] = "[SYSTEM: 已归档] 内容已移除以节省 Token。"
              artifact["is_dehydrated"] = True
            else:
              path = artifact.get("metadata", {}).get("path", "unknown.py")
              skeleton = self._generate_semantic_skeleton(artifact.get("content", ""), path)
              artifact["content"] = f"[SYSTEM: 语义骨架]\n{skeleton}"
              artifact["is_skeleton"] = True
            clean["content"] = json.dumps(data, ensure_ascii=False)

          elif artifact.get("artifact_type") == "image":
            if i != last_image_idx:
              # 如果不是最后一张图，把巨大的 base64 删掉，只留个标记
              artifact["base64"] = "[DEHYDRATED]"
              artifact["is_dehydrated"] = True
              clean["content"] = json.dumps(data, ensure_ascii=False)

        except (json.JSONDecodeError, TypeError, KeyError):
          pass

        result.append(clean)
        continue

      if tag == "DECISION":
        clean = {k: v for k, v in msg.items() if not k.startswith("_")}
        content = clean.get("content", "")
        if isinstance(content, str) and len(content) > 400:
          clean = clean.copy()
          clean["content"] = content[:400] + "\n[SYSTEM: 内容已摘要]"
        result.append(clean)
        continue

      clean = {k: v for k, v in msg.items() if not k.startswith("_")}
      if i < active_boundary and role == "assistant":
        content = clean.get("content", "")
        if isinstance(content, str) and len(content) > 300:
          clean = clean.copy()
          clean["content"] = content[:300] + "\n[SYSTEM: 已折叠]"
      result.append(clean)

    return result

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

  # ─── Session 管理 ─────────────────────────────────────────

  @classmethod
  def list_sessions(cls, memory_dir: str, role_name: str) -> List[SessionMeta]:
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
    role_dir = os.path.join(memory_dir, _safe_name(role_name))
    hist_path = os.path.join(role_dir, f"{session_id}.jsonl")
    try:
      if os.path.exists(hist_path):
        os.remove(hist_path)
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
    """打开文件句柄（修复 P1-2：由 _lock 统一保护，不再用 _file_lock）"""
    try:
      if self._file and not self._file.closed:
        self._file.close()
      self._file_path = self._history_path()
      self._file = open(self._file_path, "a", encoding="utf-8", buffering=1)
      if os.path.exists(self._file_path):
        self._verify_file_integrity()
    except Exception as e:
      print(f"[Memory] ❌ 打开文件失败: {e}")
      self._file = None
      self._file_path = None

  def _cleanup_resources(self):
    """清理资源（修复 P1-2：统一使用 _lock）"""
    with self._lock:
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
    if not self._file_path or not os.path.exists(self._file_path):
      return
    try:
      file_size = os.path.getsize(self._file_path)
      if file_size > 100 * 1024 * 1024:
        print(f"[Memory] ⚠️  文件过大: {file_size} bytes")
      with open(self._file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
          if line.strip():
            try:
              json.loads(line)
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
      return messages
    except Exception as e:
      print(f"[Memory] ❌ 加载session失败: {e}")
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
    """原子性保存meta（锁外调用，避免持锁期间做磁盘 I/O）"""
    index_path = os.path.join(self._role_dir, "sessions.json")
    temp_path = index_path + f".tmp.{int(time.time())}"
    try:
      sessions = []
      if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
          raw = json.load(f)
        sessions = raw.get("sessions", [])
      found = False
      # 读取当前 meta 快照（需要加锁）
      with self._lock:
        meta_snapshot = asdict(self._meta)
      for i, s in enumerate(sessions):
        if s["session_id"] == self._session_id:
          sessions[i] = meta_snapshot
          found = True
          break
      if not found:
        sessions.append(meta_snapshot)
      with open(temp_path, "w", encoding="utf-8") as f:
        json.dump({"sessions": sessions}, f, ensure_ascii=False, indent=2)
      os.rename(temp_path, index_path)
    except Exception as e:
      print(f"[Memory] ⚠️  保存meta失败: {e}")
      if os.path.exists(temp_path):
        try:
          os.remove(temp_path)
        except OSError:
          pass

  def _tag_importance(self, message: Dict) -> Dict:
    tagged = dict(message)
    role = message.get("role", "")
    content = message.get("content", "")
    content_str = str(content) if not isinstance(content, str) else content

    # 1. 用户消息：最高优先级
    if role == "user":
      tagged["_importance"] = "ANCHOR"
      return tagged

    # 2. 助手消息
    if role == "assistant":
      tool_calls = message.get("tool_calls", [])
      if any(tc.get("function", {}).get("name") == "submit_plan" for tc in tool_calls if isinstance(tc, dict)):
        tagged["_importance"] = "ANCHOR"
      elif len(content_str.strip()) > 50:
        tagged["_importance"] = "DECISION"
      elif not content_str.strip() and not tool_calls:
        tagged["_importance"] = "NOISE"
      else:
        tagged["_importance"] = "PROCESS"
      return tagged

    # 3. 工具消息
    if role == "tool":
      try:
        data = json.loads(content_str)
        inner_data = data.get("data", {})
        # 计划确认是锚点
        if inner_data.get("status") == "PLAN_ACCEPTED":
          tagged["_importance"] = "ANCHOR"
        # 错误或文件内容是重要决策依据 (DECISION)
        elif data.get("status") == "error" or inner_data.get("artifact_type") == "file_content":
          tagged["_importance"] = "DECISION"
        # 简短的目录列表等是噪音
        elif "entries" in inner_data and "summary_items" not in inner_data and len(str(inner_data)) < 500:
          tagged["_importance"] = "NOISE"
        else:
          tagged["_importance"] = "PROCESS"
      except (json.JSONDecodeError, AttributeError):
        tagged["_importance"] = "PROCESS"
      return tagged

    tagged["_importance"] = "PROCESS"
    return tagged

  def _group_remove(self, messages: List[Dict], indices_to_remove: set) -> List[Dict]:
    tool_call_owner: Dict[str, int] = {}
    tool_result_index: Dict[str, int] = {}
    for i, msg in enumerate(messages):
      if msg.get("role") == "assistant":
        for tc in msg.get("tool_calls", []):
          if isinstance(tc, dict) and tc.get("id"):
            tool_call_owner[tc["id"]] = i
      if msg.get("role") == "tool" and msg.get("tool_call_id"):
        tool_result_index[msg["tool_call_id"]] = i

    expanded = set(indices_to_remove)
    for idx in list(indices_to_remove):
      msg = messages[idx]
      role = msg.get("role", "")
      if role == "tool":
        tc_id = msg.get("tool_call_id", "")
        if tc_id and tc_id in tool_call_owner:
          expanded.add(tool_call_owner[tc_id])
      if role == "assistant":
        for tc in msg.get("tool_calls", []):
          if isinstance(tc, dict) and tc.get("id") in tool_result_index:
            expanded.add(tool_result_index[tc["id"]])

    return [m for i, m in enumerate(messages) if i not in expanded]

  def _maybe_trim(self):
    if (len(self._messages) <= self._max_messages and
        self._cached_token_estimate <= self._max_token_budget):
      return

    accurate = sum(self._count_tokens_single(m) for m in self._messages)
    self._cached_token_estimate = accurate
    self._last_token_calc_time = time.time()

    if accurate <= self._max_token_budget and len(self._messages) <= self._max_messages:
      return

    original_count = len(self._messages)
    noise_indices = {i for i, m in enumerate(self._messages) if m.get("_importance") == "NOISE"}
    self._messages = self._group_remove(self._messages, noise_indices)
    self._cached_token_estimate = sum(self._count_tokens_single(m) for m in self._messages)

    if (self._cached_token_estimate <= self._max_token_budget and
        len(self._messages) <= self._max_messages):
      print(f"[Memory] ✂️  NOISE 清理：{original_count} → {len(self._messages)} 条")
      return

    process_indices = [i for i, m in enumerate(self._messages) if m.get("_importance") == "PROCESS"]
    cutoff = len(process_indices) // 2
    indices_to_remove = set(process_indices[:cutoff])
    self._messages = self._group_remove(self._messages, indices_to_remove)

    self._cached_token_estimate = sum(self._count_tokens_single(m) for m in self._messages)
    self._last_token_calc_time = time.time()
    self._stats.trim_count += 1
    self._stats.last_trim_time = time.time()
    print(f"[Memory] ✂️  重要性裁剪：{original_count} → {len(self._messages)} 条")

  def _update_stats(self):
    self._stats.memory_messages = len(self._messages)
    self._stats.token_estimate = self.token_estimate()
    if self._file_path and os.path.exists(self._file_path):
      try:
        self._stats.file_size_bytes = os.path.getsize(self._file_path)
      except OSError:
        pass


# ─── 工具函数 ─────────────────────────────────────────────────

def _safe_name(name: str) -> str:
  return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)


@contextmanager
def memory_store_context(*args, **kwargs):
  store = None
  try:
    store = MemoryStore(*args, **kwargs)
    yield store
  finally:
    if store:
      store.close()
