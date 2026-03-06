"""
运行时权限管理器 v3.2 - 性能优化版（修复缓存清除问题）
优化内容：
- 添加权限匹配缓存：减少重复计算
- 优化路径匹配算法：提前返回
- 改进危险命令检测：使用集合查找
- 修复权限撤销时的缓存清除逻辑
"""

import fnmatch
import os
import threading
from typing import List, Dict, Optional

from core.manifest import Permissions


class PermissionChecker:
  """
  维护运行时权限白名单（read / write / shell）。

  性能优化：
  - 添加权限匹配缓存
  - 优化路径匹配算法
  - 改进危险命令检测
  """

  def __init__(self, init_permissions: Permissions):
    # 线程安全锁（必须最先初始化，_normalize_patterns 内部会用到 _secure_normalize）
    self._lock = threading.RLock()

    # 预编译的危险路径模式（_secure_normalize 会调用，必须在规范化前准备好）
    self._dangerous_patterns = {
      '/etc/*', '/bin/*', '/sbin/*', '/usr/bin/*', '/usr/sbin/*',
      '/boot/*', '/sys/*', '/proc/*', '/dev/*', '/root/*',
      '*/.ssh/*', '*/.gnupg/*', '*/.aws/*', '*/.config/*'
    }

    # ─── 修复：init 时就把所有 patterns 规范化为绝对路径 ───
    # 这样 _match_path 里的 pattern 和 can_* 里规范化后的 target 格式一致，才能匹配上
    self._list_patterns: List[str] = self._normalize_patterns(init_permissions.list)
    self._read_patterns: List[str] = self._normalize_patterns(init_permissions.read)
    self._write_patterns: List[str] = self._normalize_patterns(init_permissions.write)
    self._shell_prefixes: List[str] = list(init_permissions.shell)  # shell 前缀不是路径，不需规范化

    # 保存初始权限快照（revoke_all 用），同样是规范化后的
    self._init_list_patterns: List[str] = list(self._list_patterns)
    self._init_read_patterns: List[str] = list(self._read_patterns)
    self._init_write_patterns: List[str] = list(self._write_patterns)
    self._init_shell_prefixes: List[str] = list(self._shell_prefixes)

    # 性能优化：危险命令集合（使用集合查找，O(1)复杂度）
    self._dangerous_commands = {
      'rm -rf /', 'rm -rf /*', 'dd if=/dev/zero', 'mkfs',
      'chmod 777 /', 'chown root', 'sudo su', 'su root',
      ':(){ :|:& };:', 'fork bomb', 'crash', 'reboot', 'shutdown',
      'iptables -F', 'service stop', 'systemctl stop'
    }

    # 权限匹配缓存（使用LRU缓存）
    self._permission_cache: Dict[str, bool] = {}
    self._cache_max_size = 1000
    self._cache_hits = 0
    self._cache_misses = 0
    # 权限变更历史（用于审计）
    self._permission_history: List[Dict] = []
    os.makedirs("./agent_workspace", exist_ok=True)

  # ─── 权限检查 ──────────────────────────────────────────────

  def can_read(self, path: str) -> bool:
    """检查读权限（带缓存）"""
    cache_key = f"read:{path}"
    if cache_key in self._permission_cache:
      self._cache_hits += 1
      return self._permission_cache[cache_key]

    self._cache_misses += 1
    try:
      normalized_path = self._secure_normalize(path)
      if normalized_path is None:
        result = False
      else:
        result = self._match_path(normalized_path, self._read_patterns)

      # 更新缓存
      self._update_cache(cache_key, result)
      return result
    except Exception:
      # 异常情况下拒绝访问
      return False

  def can_write(self, path: str) -> bool:
    """检查写权限（带缓存）"""
    cache_key = f"write:{path}"
    if cache_key in self._permission_cache:
      self._cache_hits += 1
      return self._permission_cache[cache_key]

    self._cache_misses += 1
    try:
      normalized_path = self._secure_normalize(path)
      if normalized_path is None:
        result = False
      else:
        result = self._match_path(normalized_path, self._write_patterns)

      # 更新缓存
      self._update_cache(cache_key, result)
      return result
    except Exception:
      return False

  def can_shell(self, command: str) -> bool:
    """检查命令执行权限（带缓存）"""
    cache_key = f"shell:{command}"
    if cache_key in self._permission_cache:
      self._cache_hits += 1
      return self._permission_cache[cache_key]

    self._cache_misses += 1
    try:
      cmd = command.strip()
      if not cmd:
        result = False
      else:
        # 安全检查：禁止危险命令
        if self._is_dangerous_command(cmd):
          result = False
        else:
          # 检查是否匹配授权前缀
          result = any(
              cmd == prefix or cmd.startswith(prefix + " ")
              for prefix in self._shell_prefixes
          )

      # 更新缓存
      self._update_cache(cache_key, result)
      return result
    except Exception:
      return False

  def can_list(self, path: str) -> bool:
    """
    list_directory 检查 list 白名单（重要修复：不再复用 read 白名单）
    此方法现在直接针对 _list_patterns 进行权限匹配。
    """
    cache_key = f"list:{path}"
    if cache_key in self._permission_cache:
      self._cache_hits += 1
      return self._permission_cache[cache_key]

    self._cache_misses += 1
    try:
      normalized_path = self._secure_normalize(path)
      if normalized_path is None:
        result = False
      else:
        # **这里的核心修改：使用 self._list_patterns 进行匹配**
        result = self._match_path(normalized_path, self._list_patterns)

      self._update_cache(cache_key, result)
      return result
    except Exception:
      return False

  # ─── 白名单扩展（人类批准后调用）─────────────────────────

  def grant_read(self, paths: List[str]):
    """授予读权限（修复：在授权时一次性规范化模式，避免每次匹配重复计算）"""
    with self._lock:
      added = []
      for p in paths:
        normalized = self._secure_normalize(p)
        if normalized and normalized not in self._read_patterns:
          self._read_patterns.append(normalized)
          added.append(normalized)

      if added:
        self._record_permission_change("grant_read", added)
        self._clear_cache_for_type("read")

  def grant_write(self, paths: List[str]):
    """授予写权限"""
    with self._lock:
      added = []
      for p in paths:
        normalized = self._secure_normalize(p)
        if normalized and normalized not in self._write_patterns:
          self._write_patterns.append(normalized)
          added.append(normalized)

      if added:
        self._record_permission_change("grant_write", added)
        # 清除所有写权限缓存
        self._clear_cache_for_type("write")

  def grant_shell(self, prefixes: List[str]):
    """授予Shell命令权限"""
    with self._lock:
      added = []
      for p in prefixes:
        clean_prefix = self._clean_shell_prefix(p)
        if clean_prefix and clean_prefix not in self._shell_prefixes:
          self._shell_prefixes.append(clean_prefix)
          added.append(clean_prefix)

      if added:
        self._record_permission_change("grant_shell", added)
        # 清除所有Shell权限缓存
        self._clear_cache_for_type("shell")

  # ─── 权限撤销（新增功能）──────────────────────────────────

  def revoke_read(self, paths: List[str]):
    """撤销读权限"""
    with self._lock:
      removed = []
      for p in paths:
        normalized = self._secure_normalize(p)
        if normalized and normalized in self._read_patterns:
          self._read_patterns.remove(normalized)
          removed.append(normalized)

      if removed:
        self._record_permission_change("revoke_read", removed)
        # 清除所有读权限缓存
        self._clear_cache_for_type("read")

  def revoke_write(self, paths: List[str]):
    """撤销写权限"""
    with self._lock:
      removed = []
      for p in paths:
        normalized = self._secure_normalize(p)
        if normalized and normalized in self._write_patterns:
          self._write_patterns.remove(normalized)
          removed.append(normalized)

      if removed:
        self._record_permission_change("revoke_write", removed)
        # 清除所有写权限缓存
        self._clear_cache_for_type("write")

  def revoke_shell(self, prefixes: List[str]):
    """撤销Shell命令权限"""
    with self._lock:
      removed = []
      for p in prefixes:
        clean_prefix = self._clean_shell_prefix(p)
        if clean_prefix and clean_prefix in self._shell_prefixes:
          self._shell_prefixes.remove(clean_prefix)
          removed.append(clean_prefix)

      if removed:
        self._record_permission_change("revoke_shell", removed)
        # 清除所有Shell权限缓存
        self._clear_cache_for_type("shell")

  def revoke_all(self):
    """撤销所有动态授权权限，恢复到初始状态（修复：不再清除初始权限）"""
    with self._lock:
      before_snapshot = self.snapshot()

      # ─── 修复：恢复到初始权限，而不是清空所有 ───
      self._list_patterns = list(self._init_list_patterns)
      self._read_patterns = list(self._init_read_patterns)
      self._write_patterns = list(self._init_write_patterns)
      self._shell_prefixes = list(self._init_shell_prefixes)

      # 清除所有缓存
      self._permission_cache.clear()

      self._record_permission_change("revoke_all", {
        "before": before_snapshot,
        "after": self.snapshot()
      })

  # ─── 当前白名单快照（用于审计日志）──────────────────────

  def snapshot(self) -> dict:
    """获取当前权限白名单快照"""
    with self._lock:
      return {
        "read": list(self._read_patterns),
        "write": list(self._write_patterns),
        "shell": list(self._shell_prefixes),
        "history_count": len(self._permission_history),
        "cache_stats": {
          "hits": self._cache_hits,
          "misses": self._cache_misses,
          "size": len(self._permission_cache),
          "hit_rate": f"{self._cache_hits / (self._cache_hits + self._cache_misses) * 100:.1f}%" if (self._cache_hits + self._cache_misses) > 0 else "0%"
        }
      }

  def get_permission_history(self) -> List[Dict]:
    """获取权限变更历史"""
    with self._lock:
      return list(self._permission_history)

  # ─── 私有方法 ─────────────────────────────────────────────

  def _normalize_patterns(self, patterns: List[str]) -> List[str]:
    """
    将路径模式列表规范化为绝对路径，同时保留通配符（**、*、?）。
    例：'./core/**' → '/abs/path/core/**'
    规范化在 init 时一次性完成，避免每次匹配重复计算。
    """
    normalized = []
    for raw in patterns:
      if not raw:
        continue
      # 分离路径主体和尾部通配符段（** / * 不能直接传给 os.path.abspath）
      # 策略：找到第一个含通配符的段，对其前缀规范化，再拼回通配符后缀
      parts = raw.replace('\\', '/').split('/')
      prefix_parts = []
      wildcard_parts = []
      hit_wildcard = False
      for part in parts:
        if hit_wildcard or '*' in part or '?' in part:
          hit_wildcard = True
          wildcard_parts.append(part)
        else:
          prefix_parts.append(part)

      prefix = '/'.join(prefix_parts) if prefix_parts else '.'
      try:
        abs_prefix = os.path.abspath(os.path.expanduser(prefix))
      except Exception:
        continue

      if wildcard_parts:
        norm = abs_prefix + os.sep + os.sep.join(wildcard_parts)
        norm = os.path.normpath(norm).replace('**', '\x00').replace('*', '\x00').replace('\x00', '*')
        # normpath 会把 ** 压缩，需要还原；用占位符绕过
        # 更稳健的方式：直接字符串拼接，不走 normpath
        norm = abs_prefix + os.sep + os.sep.join(wildcard_parts)
      else:
        norm = abs_prefix

      normalized.append(norm)

    return normalized

  def _update_cache(self, key: str, value: bool):
    """更新缓存（LRU策略）"""
    # 如果缓存已满，删除最旧的条目
    if len(self._permission_cache) >= self._cache_max_size:
      # 简单的LRU：删除第一个条目
      oldest_key = next(iter(self._permission_cache))
      del self._permission_cache[oldest_key]

    self._permission_cache[key] = value

  def _clear_cache_for_type(self, perm_type: str):
    """清除指定类型的所有缓存"""
    keys_to_remove = [key for key in self._permission_cache if key.startswith(f"{perm_type}:")]
    for key in keys_to_remove:
      del self._permission_cache[key]

  def _secure_normalize(self, path: str) -> Optional[str]:
    """
    安全的路径规范化，防止路径穿越和符号链接攻击

    安全措施：
    1. 展开用户目录 (~)
    2. 解析相对路径为绝对路径
    3. 规范化路径分隔符
    4. 解析符号链接（安全地）
    5. 验证路径合法性
    """
    try:
      if not path or not isinstance(path, str):
        return None

      # 检查危险字符
      if any(char in path for char in ['\x00', '\n', '\r']):
        return None

      # 展开用户目录
      expanded = os.path.expanduser(path)

      # 转换为绝对路径
      abs_path = os.path.abspath(expanded)

      # 规范化路径（解析 .. 和 .）
      norm_path = os.path.normpath(abs_path)

      # 安全检查：确保路径不包含危险模式
      if self._matches_dangerous_pattern(norm_path):
        return None

      # 安全地解析符号链接
      real_path = self._safe_resolve_symlinks(norm_path)
      if real_path is None:
        return None

      return real_path

    except (ValueError, OSError, RuntimeError):
      return None

  def _safe_resolve_symlinks(self, path: str) -> Optional[str]:
    """
    安全地解析符号链接，防止符号链接攻击

    策略：
    1. 限制符号链接解析深度
    2. 检查循环链接
    3. 验证最终路径的安全性
    """
    max_depth = 10
    current_depth = 0
    visited_paths = set()

    try:
      current_path = path

      while current_depth < max_depth:
        if current_path in visited_paths:
          # 检测到循环链接
          return None

        visited_paths.add(current_path)

        if os.path.islink(current_path):
          # 解析符号链接
          link_target = os.readlink(current_path)

          # 处理相对路径的符号链接
          if not os.path.isabs(link_target):
            link_target = os.path.join(os.path.dirname(current_path), link_target)

          # 规范化目标路径
          current_path = os.path.normpath(link_target)
          current_depth += 1
        else:
          # 不是符号链接，返回解析后的路径
          real_path = os.path.realpath(current_path)

          # 最终安全检查
          if self._matches_dangerous_pattern(real_path):
            return None

          return real_path

      # 超过最大深度
      return None

    except (OSError, ValueError):
      return None

  def _matches_dangerous_pattern(self, path: str) -> bool:
    """检查路径是否匹配危险模式"""
    path_lower = path.lower()
    for pattern in self._dangerous_patterns:
      if fnmatch.fnmatch(path_lower, pattern.lower()):
        return True
    return False

  def _is_dangerous_command(self, command: str) -> bool:
    """检查是否为危险命令（优化版）"""
    cmd_lower = command.lower()

    # 使用集合查找，O(1)复杂度
    for dangerous in self._dangerous_commands:
      if dangerous in cmd_lower:
        return True

    # 检查是否包含管道重定向到危险位置
    dangerous_patterns = ['> /etc/', '>> /etc/', '> /bin/', '>> /bin/']
    for pattern in dangerous_patterns:
      if pattern in cmd_lower:
        return True

    return False

  def _clean_shell_prefix(self, prefix: str) -> Optional[str]:
    """清理Shell命令前缀"""
    try:
      if not prefix or not isinstance(prefix, str):
        return None

      cleaned = prefix.strip()
      if not cleaned:
        return None

      # 检查危险字符
      if any(char in cleaned for char in ['\x00', '\n', '\r']):
        return None

      # 限制长度
      if len(cleaned) > 200:
        return None

      return cleaned
    except Exception:
      return None

  def _match_path(self, normalized_path: str, patterns: List[str]) -> bool:
    """
    AntPath 风格路径匹配。
    修复：patterns 已在 grant 时规范化，无需每次重复调用 _secure_normalize。

    通配符语义（与 Spring AntPathMatcher 对齐）：
      ?   匹配单个任意字符（不含路径分隔符）
      *   匹配同一路径段内的任意字符串（不跨 /）
      **  匹配零个或多个完整路径段（可跨 /）
    """
    try:
      for pattern in patterns:
        if not pattern:
          continue
        # 修复：初始化时模式已原始字符串形式存储（grant 时已规范化）
        # 直接使用，不再重复调用 _secure_normalize
        if self._antpath_match(normalized_path, pattern):
          return True
      return False
    except Exception:
      return False

  def _antpath_match(self, path: str, pattern: str) -> bool:
    """
    核心 AntPath 匹配算法。

    实现要点：
    1. 将 path 和 pattern 均按 os.sep 拆分为段列表
    2. 用动态规划处理 ** 可匹配零到多段的情况
    3. ? 只匹配单个非分隔符字符，* 只匹配同一段内的字符串
    4. 模式末尾的 ** 额外允许匹配模式前缀本身（即父目录）
    """
    sep = os.sep

    # ── 快捷路径 ────────────────────────────────────────────
    # 精确匹配
    if path == pattern:
      return True

    # 模式不含通配符：只做精确匹配 + 子路径前缀匹配
    if '*' not in pattern and '?' not in pattern:
      return path.startswith(pattern.rstrip(sep) + sep)

    # ── 拆段 ────────────────────────────────────────────────
    path_parts = [p for p in path.split(sep) if p]
    pat_parts = [p for p in pattern.split(sep) if p]

    # ** 末尾特例：/a/b/** 也应匹配 /a/b 本身
    if pat_parts and pat_parts[-1] == '**':
      base = sep + sep.join(pat_parts[:-1])
      if path == base or path.startswith(base + sep):
        return True

    # ── 动态规划 ────────────────────────────────────────────
    # dp[i][j] = True 表示 path_parts[:i] 已被 pat_parts[:j] 完全匹配
    n, m = len(path_parts), len(pat_parts)
    dp = [[False] * (m + 1) for _ in range(n + 1)]
    dp[0][0] = True

    # 模式开头连续的 ** 可以匹配空路径
    for j in range(1, m + 1):
      if pat_parts[j - 1] == '**':
        dp[0][j] = dp[0][j - 1]
      else:
        break

    for i in range(1, n + 1):
      for j in range(1, m + 1):
        seg = pat_parts[j - 1]
        if seg == '**':
          # ** 匹配零段（跳过该模式段）或多段（消耗一个路径段）
          dp[i][j] = dp[i][j - 1] or dp[i - 1][j]
        else:
          # 单段匹配：使用 fnmatch 处理 * 和 ?
          if dp[i - 1][j - 1] and fnmatch.fnmatch(path_parts[i - 1], seg):
            dp[i][j] = True

    return dp[n][m]

  def _record_permission_change(self, change_type: str, items: List[str] | Dict):
    """记录权限变更历史"""
    import time

    change_record = {
      "timestamp": time.time(),
      "type": change_type,
      "items": items if isinstance(items, list) else [items],
      "total_patterns": {
        "read": len(self._read_patterns),
        "write": len(self._write_patterns),
        "shell": len(self._shell_prefixes),
      }
    }

    self._permission_history.append(change_record)

    # 限制历史记录数量
    if len(self._permission_history) > 1000:
      self._permission_history = self._permission_history[-500:]
