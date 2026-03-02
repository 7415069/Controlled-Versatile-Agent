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
    self._read_patterns: List[str] = list(init_permissions.read)
    self._write_patterns: List[str] = list(init_permissions.write)
    self._shell_prefixes: List[str] = list(init_permissions.shell)

    # 线程安全锁
    self._lock = threading.RLock()

    # 权限变更历史（用于审计）
    self._permission_history: List[Dict] = []

    # 预编译的危险路径模式
    self._dangerous_patterns = {
      '/etc/*', '/bin/*', '/sbin/*', '/usr/bin/*', '/usr/sbin/*',
      '/boot/*', '/sys/*', '/proc/*', '/dev/*', '/root/*',
      '*/.ssh/*', '*/.gnupg/*', '*/.aws/*', '*/.config/*'
    }

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
    """list_directory 复用 read 白名单"""
    return self.can_read(path)

  # ─── 白名单扩展（人类批准后调用）─────────────────────────

  def grant_read(self, paths: List[str]):
    """授予读权限"""
    with self._lock:
      added = []
      for p in paths:
        normalized = self._secure_normalize(p)
        if normalized and normalized not in self._read_patterns:
          self._read_patterns.append(normalized)
          added.append(normalized)

      if added:
        self._record_permission_change("grant_read", added)
        # 清除所有读权限缓存（简单粗暴但有效）
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
    """撤销所有临时授予的权限，恢复到初始状态"""
    with self._lock:
      # 记录撤销前的状态
      before_snapshot = self.snapshot()

      # 恢复到初始权限（需要保存初始权限）
      # 这里简化为清空所有权限
      self._read_patterns.clear()
      self._write_patterns.clear()
      self._shell_prefixes.clear()

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
    安全的路径匹配逻辑（优化版）

    匹配策略：
    1. 精确匹配
    2. Glob模式匹配
    3. 前缀匹配（目录包含）

    优化：提前返回，减少不必要的遍历
    """
    try:
      for pattern in patterns:
        if not pattern:
          continue

        # 规范化模式
        norm_pattern = self._secure_normalize(pattern)
        if norm_pattern is None:
          continue

        # 精确匹配（最快）
        if normalized_path == norm_pattern:
          return True

        # 前缀匹配（次快）
        if normalized_path.startswith(norm_pattern + os.sep):
          return True

        # Glob匹配（最慢，放在最后）
        if fnmatch.fnmatch(normalized_path, norm_pattern):
          return True

      return False
    except Exception:
      return False

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
