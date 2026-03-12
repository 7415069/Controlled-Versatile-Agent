"""
运行时权限管理器 v4.1
修复：can_shell() 使用 shlex 解析第一个 token 做比对，并拦截链式符号（; && || |）
"""

import os
import shlex
import threading
import time
from typing import List, Dict, Optional, Union

import pathspec

from core.config import cva_settings
from core.manifest import Permissions

# 链式执行符：出现任意一个就拒绝整条命令
_CHAIN_OPERATORS = {";", "&&", "||", "|", "`", "$("}


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
    normalized = []
    for p in patterns:
      if p.startswith('!./'):
        normalized.append('!' + p[3:])
      elif p.startswith('./'):
        normalized.append(p[2:])
      else:
        normalized.append(p)
    return pathspec.PathSpec.from_lines('gitignore', normalized)

  def _match_spec(self, spec: pathspec.PathSpec, abs_path: str) -> bool:
    try:
      rel = os.path.relpath(abs_path, self._root)
      if spec.match_file(rel):
        return True
      return spec.match_file(rel + '/')
    except ValueError:
      return False

  # ─── 权限检查 ──────────────────────────────────────────────

  def can_read(self, path: str) -> bool:
    return self._check_path('read', path, self._read_spec)

  def can_write(self, path: str) -> bool:
    return self._check_path('write', path, self._write_spec)

  def can_list(self, path: str) -> bool:
    return self._check_path('list', path, self._list_spec)

  def can_shell(self, command: str) -> bool:
    """
    检查命令执行权限。

    修复要点（P0 安全漏洞）：
      1. 用 shlex.split() 解析命令，取第一个 token 做白名单比对，
         防止 "grep; rm -rf /" 之类以合法前缀开头的注入绕过。
      2. 遍历所有 token 检测链式操作符（; && || | ` $(）），
         发现即拒绝，避免命令拼接注入。
      3. 保留原有危险命令黑名单检查。
    """
    cache_key = f'shell:{command}'
    with self._lock:
      if cache_key in self._permission_cache:
        self._cache_hits += 1
        return self._permission_cache[cache_key]

    self._cache_misses += 1
    result = self._evaluate_shell(command)
    self._update_cache(cache_key, result)
    return result

  def _evaluate_shell(self, command: str) -> bool:
    cmd = command.strip()
    if not cmd:
      return False

    # 1. 整体黑名单检查
    if self._is_dangerous_command(cmd):
      return False

    # 2. 链式操作符检测（遍历原始字符串，防止编码绕过）
    #    先用简单字符串检测快速拦截最常见形式
    for op in (";", "&&", "||", "`", "$("):
      if op in cmd:
        return False

    # 3. 用 shlex 解析，取第一个 token 做白名单匹配
    try:
      tokens = shlex.split(cmd)
    except ValueError:
      # shlex 解析失败（引号不匹配等），视为可疑，拒绝
      return False

    if not tokens:
      return False

    # 再次检查每个 token 是否含链式操作符（防止编码绕过 shlex 的情况）
    for token in tokens:
      if token in (";", "&&", "||", "|", "`"):
        return False

    first_token = tokens[0]

    # 4. 白名单前缀比对：只比较第一个 token
    return any(
        first_token == prefix or first_token == prefix.split()[0]
        for prefix in self._shell_prefixes
        if prefix
    )

  def _check_path(self, perm_type: str, path: str, spec: pathspec.PathSpec) -> bool:
    cache_key = f'{perm_type}:{path}'
    with self._lock:
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
    with self._lock:
      self._read_patterns.extend(paths)
      self._read_spec = self._build_spec(self._read_patterns)
      self._clear_cache_for_type('read')
      self._record_permission_change('grant_read', paths)

  def grant_write(self, paths: List[str]):
    with self._lock:
      self._write_patterns.extend(paths)
      self._write_spec = self._build_spec(self._write_patterns)
      self._clear_cache_for_type('write')
      self._record_permission_change('grant_write', paths)

  def grant_shell(self, prefixes: List[str]):
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
    with self._lock:
      self._read_patterns = [p for p in self._read_patterns if p not in paths]
      self._read_spec = self._build_spec(self._read_patterns)
      self._clear_cache_for_type('read')
      self._record_permission_change('revoke_read', paths)

  def revoke_write(self, paths: List[str]):
    with self._lock:
      self._write_patterns = [p for p in self._write_patterns if p not in paths]
      self._write_spec = self._build_spec(self._write_patterns)
      self._clear_cache_for_type('write')
      self._record_permission_change('revoke_write', paths)

  def revoke_shell(self, prefixes: List[str]):
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
    with self._lock:
      return list(self._permission_history)

  # ─── 私有方法 ─────────────────────────────────────────────

  def _secure_normalize(self, path: str) -> Optional[str]:
    try:
      if not path or not isinstance(path, str):
        return None
      if any(c in path for c in ['\x00', '\n', '\r']):
        return None

      abs_path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))

      for prefix in self._dangerous_path_prefixes:
        if abs_path == prefix or abs_path.startswith(prefix + os.sep):
          return None

      return self._safe_resolve_symlinks(abs_path)
    except (ValueError, OSError, RuntimeError):
      return None

  def _safe_resolve_symlinks(self, path: str) -> Optional[str]:
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
    cmd_lower = command.lower()
    for dangerous in self._dangerous_commands:
      if dangerous in cmd_lower:
        return True
    for pattern in ['> /etc/', '>> /etc/', '> /bin/', '>> /bin/']:
      if pattern in cmd_lower:
        return True
    return False

  def _clean_shell_prefix(self, prefix: str) -> Optional[str]:
    if not prefix or not isinstance(prefix, str):
      return None
    cleaned = prefix.strip()
    if not cleaned or any(c in cleaned for c in ['\x00', '\n', '\r']):
      return None
    if len(cleaned) > 200:
      return None
    return cleaned

  def _update_cache(self, key: str, value: bool):
    with self._lock:
      if len(self._permission_cache) >= self._cache_max_size:
        del self._permission_cache[next(iter(self._permission_cache))]
      self._permission_cache[key] = value

  def _clear_cache_for_type(self, perm_type: str):
    # 调用时已持有 _lock
    for key in [k for k in self._permission_cache if k.startswith(f'{perm_type}:')]:
      del self._permission_cache[key]

  def _record_permission_change(self, change_type: str, items: Union[List, Dict]):
    # 调用时已持有 _lock
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
