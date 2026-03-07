"""
运行时权限管理器 v4.0 - pathspec 版
变更：
- 使用 pathspec 库替换自实现的 AntPath 匹配算法（删除 _normalize_patterns / _match_path / _antpath_match）
- list / read / write 支持 ! 排除语法（gitignore 风格）
  示例：
    read:
      - "./core/**"
      - "!./.venv/**"
      - "!./**/__pycache__/**"
- 路径匹配改为相对路径，与 pathspec 的 gitwildmatch 语义一致
"""

import os
import threading
import time
from typing import List, Dict, Optional, Union

import pathspec

from core.config import cva_settings
from core.manifest import Permissions


class PermissionChecker:
  """
  维护运行时权限白名单（list / read / write / shell）。

  路径模式使用 gitignore / gitwildmatch 风格（由 pathspec 库处理）：
    ./core/**          匹配 core 目录下所有内容
    !./.venv/**        排除 .venv 目录（! 前缀）
    ./**/__pycache__   排除所有 __pycache__
  """

  def __init__(self, init_permissions: Permissions):
    self._lock = threading.RLock()

    # 工作根目录（相对路径基准）
    self._root = os.path.abspath('.')

    # 危险路径前缀（_secure_normalize 安全检查用）
    self._dangerous_path_prefixes = {
      '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin',
      '/boot', '/sys', '/proc', '/dev', '/root',
    }

    # 危险命令集合
    self._dangerous_commands = {
      'rm -rf /', 'rm -rf /*', 'dd if=/dev/zero', 'mkfs',
      'chmod 777 /', 'chown root', 'sudo su', 'su root',
      ':(){ :|:& };:', 'fork bomb', 'crash', 'reboot', 'shutdown',
      'iptables -F', 'service stop', 'systemctl stop',
    }

    # 保存原始模式列表（revoke_all / grant 追加用）
    self._init_list_patterns: List[str] = list(init_permissions.list)
    self._init_read_patterns: List[str] = list(init_permissions.read)
    self._init_write_patterns: List[str] = list(init_permissions.write)
    self._init_shell_prefixes: List[str] = list(init_permissions.shell)

    # 运行时可变的模式列表
    self._list_patterns: List[str] = list(self._init_list_patterns)
    self._read_patterns: List[str] = list(self._init_read_patterns)
    self._write_patterns: List[str] = list(self._init_write_patterns)
    self._shell_prefixes: List[str] = list(self._init_shell_prefixes)

    # 构建 pathspec 对象
    self._list_spec = self._build_spec(self._list_patterns)
    self._read_spec = self._build_spec(self._read_patterns)
    self._write_spec = self._build_spec(self._write_patterns)

    # 权限匹配缓存
    self._permission_cache: Dict[str, bool] = {}
    self._cache_max_size = 1000
    self._cache_hits = 0
    self._cache_misses = 0

    # 权限变更历史（审计用）
    self._permission_history: List[Dict] = []

    os.makedirs(cva_settings.agent_dir, exist_ok=True)

  # ─── pathspec 核心 ────────────────────────────────────────

  def _build_spec(self, patterns: List[str]) -> pathspec.PathSpec:
    """
    将模式列表构建为 pathspec 对象。
    gitwildmatch 原生支持 ! 排除、** 跨目录匹配。
    pathspec 不识别 ./ 前缀，构建时统一去掉。
    """
    normalized = []
    for p in patterns:
      if p.startswith('!./'):
        normalized.append('!' + p[3:])
      elif p.startswith('./'):
        normalized.append(p[2:])
      else:
        normalized.append(p)
    return pathspec.PathSpec.from_lines('gitwildmatch', normalized)

  def _match_spec(self, spec: pathspec.PathSpec, abs_path: str) -> bool:
    """
    检查绝对路径是否匹配 spec。
    转为相对于工作根目录的相对路径后交给 pathspec 判断。
    目录路径加尾部斜杠，确保 core/** 能匹配 core 目录本身。
    """
    try:
      rel = os.path.relpath(abs_path, self._root)
      if spec.match_file(rel):
        return True
      # 目录需要加尾部斜杠才能被 gitwildmatch 的 dir/** 模式匹配到
      return spec.match_file(rel + '/')
    except ValueError:
      return False

  # ─── 权限检查 ──────────────────────────────────────────────

  def can_read(self, path: str) -> bool:
    """检查读权限"""
    return self._check_path('read', path, self._read_spec)

  def can_write(self, path: str) -> bool:
    """检查写权限"""
    return self._check_path('write', path, self._write_spec)

  def can_list(self, path: str) -> bool:
    """检查目录列举权限"""
    return self._check_path('list', path, self._list_spec)

  def can_shell(self, command: str) -> bool:
    """检查命令执行权限"""
    cache_key = f'shell:{command}'
    if cache_key in self._permission_cache:
      self._cache_hits += 1
      return self._permission_cache[cache_key]

    self._cache_misses += 1
    try:
      cmd = command.strip()
      if not cmd:
        result = False
      elif self._is_dangerous_command(cmd):
        result = False
      else:
        result = any(
            cmd == prefix or cmd.startswith(prefix + ' ')
            for prefix in self._shell_prefixes
        )
      self._update_cache(cache_key, result)
      return result
    except Exception:
      return False

  def _check_path(self, perm_type: str, path: str, spec: pathspec.PathSpec) -> bool:
    """通用路径权限检查（带缓存）"""
    cache_key = f'{perm_type}:{path}'
    if cache_key in self._permission_cache:
      self._cache_hits += 1
      return self._permission_cache[cache_key]

    self._cache_misses += 1
    try:
      normalized = self._secure_normalize(path)
      result = False if normalized is None else self._match_spec(spec, normalized)
      self._update_cache(cache_key, result)
      return result
    except Exception:
      return False

  # ─── 白名单扩展（人类批准后调用）─────────────────────────

  def grant_read(self, paths: List[str]):
    """追加读权限模式（支持 ! 排除语法）"""
    with self._lock:
      self._read_patterns.extend(paths)
      self._read_spec = self._build_spec(self._read_patterns)
      self._clear_cache_for_type('read')
      self._record_permission_change('grant_read', paths)

  def grant_write(self, paths: List[str]):
    """追加写权限模式（支持 ! 排除语法）"""
    with self._lock:
      self._write_patterns.extend(paths)
      self._write_spec = self._build_spec(self._write_patterns)
      self._clear_cache_for_type('write')
      self._record_permission_change('grant_write', paths)

  def grant_shell(self, prefixes: List[str]):
    """追加 Shell 命令前缀"""
    with self._lock:
      added = []
      for p in prefixes:
        clean = self._clean_shell_prefix(p)
        if clean and clean not in self._shell_prefixes:
          self._shell_prefixes.append(clean)
          added.append(clean)
      if added:
        self._clear_cache_for_type('shell')
        self._record_permission_change('grant_shell', added)

  # ─── 权限撤销 ──────────────────────────────────────────────

  def revoke_read(self, paths: List[str]):
    """从读权限模式列表中移除指定模式"""
    with self._lock:
      self._read_patterns = [p for p in self._read_patterns if p not in paths]
      self._read_spec = self._build_spec(self._read_patterns)
      self._clear_cache_for_type('read')
      self._record_permission_change('revoke_read', paths)

  def revoke_write(self, paths: List[str]):
    """从写权限模式列表中移除指定模式"""
    with self._lock:
      self._write_patterns = [p for p in self._write_patterns if p not in paths]
      self._write_spec = self._build_spec(self._write_patterns)
      self._clear_cache_for_type('write')
      self._record_permission_change('revoke_write', paths)

  def revoke_shell(self, prefixes: List[str]):
    """移除 Shell 命令前缀"""
    with self._lock:
      removed = []
      for p in prefixes:
        clean = self._clean_shell_prefix(p)
        if clean and clean in self._shell_prefixes:
          self._shell_prefixes.remove(clean)
          removed.append(clean)
      if removed:
        self._clear_cache_for_type('shell')
        self._record_permission_change('revoke_shell', removed)

  def revoke_all(self):
    """恢复到初始权限状态"""
    with self._lock:
      before = self.snapshot()
      self._list_patterns = list(self._init_list_patterns)
      self._read_patterns = list(self._init_read_patterns)
      self._write_patterns = list(self._init_write_patterns)
      self._shell_prefixes = list(self._init_shell_prefixes)
      self._list_spec = self._build_spec(self._list_patterns)
      self._read_spec = self._build_spec(self._read_patterns)
      self._write_spec = self._build_spec(self._write_patterns)
      self._permission_cache.clear()
      self._record_permission_change('revoke_all', {
        'before': before,
        'after': self.snapshot(),
      })

  # ─── 审计接口 ──────────────────────────────────────────────

  def snapshot(self) -> dict:
    """获取当前权限快照"""
    with self._lock:
      total = self._cache_hits + self._cache_misses
      return {
        'list': list(self._list_patterns),
        'read': list(self._read_patterns),
        'write': list(self._write_patterns),
        'shell': list(self._shell_prefixes),
        'history_count': len(self._permission_history),
        'cache_stats': {
          'hits': self._cache_hits,
          'misses': self._cache_misses,
          'size': len(self._permission_cache),
          'hit_rate': f'{self._cache_hits / total * 100:.1f}%' if total > 0 else '0%',
        },
      }

  def get_permission_history(self) -> List[Dict]:
    """获取权限变更历史"""
    with self._lock:
      return list(self._permission_history)

  # ─── 私有方法 ─────────────────────────────────────────────

  def _secure_normalize(self, path: str) -> Optional[str]:
    """安全路径规范化，防止路径穿越和符号链接攻击"""
    try:
      if not path or not isinstance(path, str):
        return None
      if any(c in path for c in ['\x00', '\n', '\r']):
        return None

      abs_path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))

      # 检查危险路径前缀
      for prefix in self._dangerous_path_prefixes:
        if abs_path == prefix or abs_path.startswith(prefix + os.sep):
          return None

      return self._safe_resolve_symlinks(abs_path)
    except (ValueError, OSError, RuntimeError):
      return None

  def _safe_resolve_symlinks(self, path: str) -> Optional[str]:
    """安全解析符号链接，防止循环链接和深度攻击"""
    visited: set = set()
    current = path
    for _ in range(10):
      if current in visited:
        return None
      visited.add(current)
      if os.path.islink(current):
        target = os.readlink(current)
        if not os.path.isabs(target):
          target = os.path.join(os.path.dirname(current), target)
        current = os.path.normpath(target)
      else:
        return os.path.realpath(current)
    return None

  def _is_dangerous_command(self, command: str) -> bool:
    """检查危险命令"""
    cmd_lower = command.lower()
    for dangerous in self._dangerous_commands:
      if dangerous in cmd_lower:
        return True
    for pattern in ['> /etc/', '>> /etc/', '> /bin/', '>> /bin/']:
      if pattern in cmd_lower:
        return True
    return False

  def _clean_shell_prefix(self, prefix: str) -> Optional[str]:
    """清理 Shell 命令前缀"""
    if not prefix or not isinstance(prefix, str):
      return None
    cleaned = prefix.strip()
    if not cleaned or any(c in cleaned for c in ['\x00', '\n', '\r']):
      return None
    if len(cleaned) > 200:
      return None
    return cleaned

  def _update_cache(self, key: str, value: bool):
    """更新 LRU 缓存"""
    if len(self._permission_cache) >= self._cache_max_size:
      del self._permission_cache[next(iter(self._permission_cache))]
    self._permission_cache[key] = value

  def _clear_cache_for_type(self, perm_type: str):
    """清除指定类型的缓存"""
    for key in [k for k in self._permission_cache if k.startswith(f'{perm_type}:')]:
      del self._permission_cache[key]

  def _record_permission_change(self, change_type: str, items: Union[List, Dict]):
    """记录权限变更历史"""
    self._permission_history.append({
      'timestamp': time.time(),
      'type': change_type,
      'items': items if isinstance(items, list) else [items],
      'total_patterns': {
        'read': len(self._read_patterns),
        'write': len(self._write_patterns),
        'shell': len(self._shell_prefixes),
      },
    })
    if len(self._permission_history) > 1000:
      self._permission_history = self._permission_history[-500:]
