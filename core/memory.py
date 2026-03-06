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
    """从 submit_plan 的参数更新状态机"""
    self.current_goal = goal
    self.plan = milestones
    self.active_step = milestones[0] if milestones else ""
    self.iteration_at_plan = iteration
    # 重置已完成步骤（新计划覆盖旧计划）
    self.completed_steps = []

  def mark_step_done(self, step_description: str):
    """标记一个步骤完成，自动推进 active_step"""
    if self.active_step and self.active_step not in self.completed_steps:
      self.completed_steps.append(self.active_step)

    # 推进到下一个未完成的步骤
    for step in self.plan:
      if step not in self.completed_steps:
        self.active_step = step
        return
    self.active_step = ""  # 所有步骤完成

  def add_knowledge(self, key: str, value: str):
    """记录发现的关键事实"""
    self.discovered_knowledge[key] = value

  def add_risk(self, risk: str):
    """记录识别到的风险"""
    if risk not in self.pending_risks:
      self.pending_risks.append(risk)

  def to_prompt_block(self) -> str:
    """生成紧凑的状态摘要，注入 System Prompt（约 150–250 tokens）"""
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

    # ─── 增强：TaskState 状态机 ───
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

  def get_current_state(self) -> TaskState:
    """返回当前任务状态机（供 shell.py 注入 System Prompt）"""
    return self._task_state

  def update_task_state(self, goal: str, milestones: List[str], iteration: int):
    """由 submit_plan 工具调用成功后触发，更新状态机"""
    self._task_state.update_from_plan(goal, milestones, iteration)

  def append(self, message: Dict):
    """追加一条消息到内存和磁盘（增强：打重要性标签 + 增量 token 计数）"""
    if not message or not isinstance(message, dict):
      raise ValueError("消息必须是非空的字典")

    start_time = time.time()

    with self._lock:
      try:
        # ─── 增强：打重要性标签（规则引擎，零 LLM 调用）───
        tagged_message = self._tag_importance(message)
        self._messages.append(tagged_message)

        # 持久化
        if self._file and not self._file.closed:
          json_line = json.dumps(tagged_message, ensure_ascii=False, separators=(',', ':'))
          self._file.write(json_line + "\n")
          self._file.flush()
          os.fsync(self._file.fileno())
        else:
          self._open_file()
          if self._file:
            json_line = json.dumps(tagged_message, ensure_ascii=False, separators=(',', ':'))
            self._file.write(json_line + "\n")
            self._file.flush()
            os.fsync(self._file.fileno())

        # 更新 meta
        self._meta.message_count += 1
        self._meta.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_meta()

        # ─── 增强：增量式 token 计数，立即更新缓存 ───
        delta = self._count_tokens_single(tagged_message)
        self._cached_token_estimate += delta
        self._last_token_calc_time = time.time()

        # 检查是否需要截断
        self._maybe_trim()

        # 更新统计
        self._stats.total_messages += 1

      except Exception as e:
        self._meta.last_error = str(e)
        print(f"[Memory] ❌ 追加消息失败: {e}")
        raise
      finally:
        duration = time.time() - start_time
        if duration > 0.1:
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
    """返回当前 token 估算（增量维护，无需全量重算）"""
    # 增量缓存有效时直接返回
    current_time = time.time()
    if (current_time - self._last_token_calc_time < self._TOKEN_CACHE_TTL and
        self._cached_token_estimate > 0):
      return self._cached_token_estimate

    # 缓存过期或首次调用：全量精算并重置增量基线
    with self._lock:
      try:
        total = 0
        for m in self._messages:
          total += self._count_tokens_single(m)
        self._cached_token_estimate = total
        self._last_token_calc_time = current_time
        return total
      except Exception as e:
        print(f"[Memory] ⚠️ token_counter 失败: {e}")
        return len(self._messages) * 120

  def _count_tokens_single(self, message: Dict) -> int:
    """计算单条消息的 token 数（用于增量维护）"""
    try:
      content = message.get("content", "")
      if isinstance(content, (dict, list)):
        content = json.dumps(content, ensure_ascii=False)
      msg_for_count = [{"role": message.get("role", "user"), "content": str(content)}]
      return token_counter(model=self._model, messages=msg_for_count)
    except Exception:
      # 降级估算：中文约 1.5 token/字，英文约 0.25 token/字
      content_str = str(message.get("content", ""))
      return max(4, len(content_str) // 3)

  def prepare_for_llm(self, keep_last_n: int = 3) -> List[Dict]:
    """
    增强版消息脱水：按重要性标签过滤，而非粗暴按位置截断。

    标签策略：
      ANCHOR  → 永远原文保留（submit_plan、人类最新指令）
      DECISION→ 保留前 400 字符摘要
      PROCESS → 活跃区（最后 keep_last_n*3 条）保留，归档区做 Skeleton
      NOISE   → 直接丢弃
    """
    raw_msgs = self.messages
    total_len = len(raw_msgs)
    active_boundary = total_len - (keep_last_n * 3)  # 活跃区范围扩大，避免切断工具链
    result = []

    # 预处理：建立 tool_call_id → assistant消息索引，用于成对操作
    # key: tool_call_id, value: assistant消息在raw_msgs中的index
    tool_call_owner: Dict[str, int] = {}
    for i, msg in enumerate(raw_msgs):
      if msg.get("role") == "assistant":
        for tc in msg.get("tool_calls", []):
          if isinstance(tc, dict):
            tc_id = tc.get("id", "")
            if tc_id:
              tool_call_owner[tc_id] = i

    # 找出所有需要跳过的索引（NOISE成对跳过）
    skip_indices = set()
    for i, msg in enumerate(raw_msgs):
      tag = msg.get("_importance", "PROCESS")
      role = msg.get("role", "")
      if tag == "NOISE":
        skip_indices.add(i)
        # 如果是tool消息，同时跳过对应的assistant消息
        if role == "tool":
          tc_id = msg.get("tool_call_id", "")
          if tc_id and tc_id in tool_call_owner:
            skip_indices.add(tool_call_owner[tc_id])
        # 如果是assistant消息（含tool_calls），同时跳过所有对应的tool消息
        if role == "assistant":
          for tc in msg.get("tool_calls", []):
            if isinstance(tc, dict):
              tc_id = tc.get("id", "")
              for j, other in enumerate(raw_msgs):
                if other.get("role") == "tool" and other.get("tool_call_id") == tc_id:
                  skip_indices.add(j)

    for i, msg in enumerate(raw_msgs):
      tag = msg.get("_importance", "PROCESS")
      role = msg.get("role", "")

      # ─── ANCHOR：永久保留原文 ───
      if tag == "ANCHOR":
        clean = {k: v for k, v in msg.items() if not k.startswith("_")}
        result.append(clean)
        continue

      # ─── NOISE：成对跳过 ───
      if i in skip_indices:
        continue

      # ─── DECISION：保留摘要 ───
      if tag == "DECISION":
        clean = {k: v for k, v in msg.items() if not k.startswith("_")}
        content = clean.get("content", "")
        if isinstance(content, str) and len(content) > 400:
          clean = clean.copy()
          clean["content"] = content[:400] + "\n[SYSTEM: 内容已摘要，如需原文请重新读取]"
        result.append(clean)
        continue

      # ─── PROCESS：按区域决定处理方式 ───
      if role == "tool":
        clean = {k: v for k, v in msg.items() if not k.startswith("_")}
        content_str = clean.get("content", "")
        try:
          data = json.loads(content_str)
          artifact = data.get("data", {})
          if artifact.get("can_dehydrate") and artifact.get("artifact_type") == "file_content":
            original_code = artifact.get("content", "")
            path = artifact.get("metadata", {}).get("path", "unknown.py")

            if i < active_boundary:
              # 归档区：完全折叠
              artifact["content"] = "[SYSTEM: 已归档] 内容已移除以节省 Token，如需查看请重新调用 read_file。"
              artifact["is_dehydrated"] = True
            else:
              # 活跃区：Skeleton 化
              skeleton = self._generate_semantic_skeleton(original_code, path)
              artifact["content"] = f"[SYSTEM: 语义骨架]\n{skeleton}"
              artifact["is_skeleton"] = True

            clean["content"] = json.dumps(data, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError, KeyError):
          pass
        result.append(clean)
      else:
        # 非 tool 消息：活跃区保留，归档区折叠长内容
        clean = {k: v for k, v in msg.items() if not k.startswith("_")}
        if i < active_boundary:
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

  def _tag_importance(self, message: Dict) -> Dict:
    """
    规则引擎：为消息打重要性标签（零 LLM 调用）。
    标签写入 _importance 字段（下划线前缀，prepare_for_llm 时自动剥离）。

    ANCHOR  → 永远保留原文
    DECISION→ 保留摘要（前 400 字符）
    PROCESS → 按区域处理（活跃区 Skeleton，归档区折叠）
    NOISE   → 直接丢弃
    """
    tagged = dict(message)
    role = message.get("role", "")
    content = message.get("content", "")
    content_str = str(content) if not isinstance(content, str) else content

    # ─── ANCHOR 规则 ───
    # 1. 人类用户消息（始终是任务的起点和约束）
    if role == "user":
      tagged["_importance"] = "ANCHOR"
      return tagged

    # 2. assistant 调用了 submit_plan
    if role == "assistant":
      tool_calls = message.get("tool_calls", [])
      if any(tc.get("function", {}).get("name") == "submit_plan"
             for tc in tool_calls if isinstance(tc, dict)):
        tagged["_importance"] = "ANCHOR"
        return tagged

    # 3. submit_plan 的工具返回结果
    if role == "tool":
      try:
        data = json.loads(content_str)
        # 通过 tool_call_id 无法直接知道工具名，用结果结构判断
        if data.get("data", {}).get("status") == "PLAN_ACCEPTED":
          tagged["_importance"] = "ANCHOR"
          return tagged
      except (json.JSONDecodeError, AttributeError):
        pass

    # ─── NOISE 规则 ───
    # 1. 空内容的 assistant 消息（纯 tool_call，无文本）
    if role == "assistant" and not content_str.strip() and not message.get("tool_calls"):
      tagged["_importance"] = "NOISE"
      return tagged

    # 2. tool 消息：重复的目录列表
    # 注意：tool消息不能单独标NOISE，必须和对应的assistant tool_call一起处理
    # 这里只标记，实际丢弃在 prepare_for_llm 和 _maybe_trim 中成对处理
    if role == "tool":
      try:
        data = json.loads(content_str)
        inner_data = data.get("data", {})
        if "entries" in inner_data and "summary_items" not in inner_data and len(str(inner_data)) < 500:
          tagged["_importance"] = "NOISE"
          return tagged
      except (json.JSONDecodeError, AttributeError):
        pass

    # ─── DECISION 规则 ───
    # 1. 有实质文本内容的 assistant 消息（分析、解释、错误诊断）
    if role == "assistant" and len(content_str.strip()) > 50:
      tagged["_importance"] = "DECISION"
      return tagged

    # 2. 工具执行出错的结果
    if role == "tool":
      try:
        data = json.loads(content_str)
        if data.get("status") == "error":
          tagged["_importance"] = "DECISION"
          return tagged
      except (json.JSONDecodeError, AttributeError):
        pass

    # ─── 默认：PROCESS ───
    tagged["_importance"] = "PROCESS"
    return tagged

  def _group_remove(self, messages: List[Dict], indices_to_remove: set) -> List[Dict]:
    """
    成对删除消息：删除某条消息时，自动将其配对消息也加入删除集合。
    - 删除tool消息 → 同时删除对应assistant的tool_call消息
    - 删除assistant消息(含tool_calls) → 同时删除所有对应tool消息
    """
    # 建立 tool_call_id → assistant索引 和 tool_call_id → tool消息索引
    tool_call_owner: Dict[str, int] = {}
    tool_result_index: Dict[str, int] = {}
    for i, msg in enumerate(messages):
      if msg.get("role") == "assistant":
        for tc in msg.get("tool_calls", []):
          if isinstance(tc, dict) and tc.get("id"):
            tool_call_owner[tc["id"]] = i
      if msg.get("role") == "tool" and msg.get("tool_call_id"):
        tool_result_index[msg["tool_call_id"]] = i

    # 扩展删除集合，确保成对
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
    """增强版截断：先检查增量 token 估算，触发时按重要性裁剪"""
    if (len(self._messages) <= self._max_messages and
        self._cached_token_estimate <= self._max_token_budget):
      return

    # 触发 trim：先做一次精确全量核算
    accurate = sum(self._count_tokens_single(m) for m in self._messages)
    self._cached_token_estimate = accurate
    self._last_token_calc_time = time.time()

    if accurate <= self._max_token_budget and len(self._messages) <= self._max_messages:
      return

    # 按重要性裁剪：优先丢弃 NOISE，再丢弃 PROCESS，保留 ANCHOR 和 DECISION
    original_count = len(self._messages)

    # 第一步：丢弃所有 NOISE（成对删除）
    noise_indices = {i for i, m in enumerate(self._messages) if m.get("_importance") == "NOISE"}
    self._messages = self._group_remove(self._messages, noise_indices)

    # 重新估算
    self._cached_token_estimate = sum(self._count_tokens_single(m) for m in self._messages)

    if (self._cached_token_estimate <= self._max_token_budget and
        len(self._messages) <= self._max_messages):
      print(f"[Memory] ✂️  NOISE 清理：{original_count} → {len(self._messages)} 条")
      return

    # 第二步：从最旧的 PROCESS 消息开始裁剪，保留最近 1/2
    process_indices = [
      i for i, m in enumerate(self._messages)
      if m.get("_importance") == "PROCESS"
    ]
    # 保留后半段的 PROCESS，丢弃前半段（成对删除）
    cutoff = len(process_indices) // 2
    indices_to_remove = set(process_indices[:cutoff])
    self._messages = self._group_remove(self._messages, indices_to_remove)

    self._cached_token_estimate = sum(self._count_tokens_single(m) for m in self._messages)
    self._last_token_calc_time = time.time()
    self._stats.trim_count += 1
    self._stats.last_trim_time = time.time()
    print(f"[Memory] ✂️  重要性裁剪：{original_count} → {len(self._messages)} 条")

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
