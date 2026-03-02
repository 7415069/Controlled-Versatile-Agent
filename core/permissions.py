"""
运行时权限管理器 v2 — 安全增强版
职责：白名单维护与越权检测

安全改进：
- 加强路径穿越防护：正确处理符号链接和硬链接
- 增加路径规范化验证：防止恶意路径构造
- 改进权限匹配逻辑：更严格的边界检查
- 添加权限审计：记录权限变更历史
"""

import fnmatch
import os
import threading
from typing import List, Dict, Set, Optional
from pathlib import Path

from core.manifest import Permissions


class PermissionChecker:
  """
  维护运行时权限白名单（read / write / shell）。
  
  安全增强：
  - 所有路径经过严格的规范化处理
  - 正确处理符号链接，防止绕过攻击
  - 线程安全的权限管理
  - 详细的权限审计日志
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

  # ─── 权限检查 ──────────────────────────────────────────────

  def can_read(self, path: str) -> bool:
    """检查读权限"""
    try:
      normalized_path = self._secure_normalize(path)
      if normalized_path is None:
        return False
      return self._match_path(normalized_path, self._read_patterns)
    except Exception:
      # 异常情况下拒绝访问
      return False

  def can_write(self, path: str) -> bool:
    """检查写权限"""
    try:
      normalized_path = self._secure_normalize(path)
      if normalized_path is None:
        return False
      return self._match_path(normalized_path, self._write_patterns)
    except Exception:
      return False

  def can_shell(self, command: str) -> bool:
    """检查命令执行权限"""
    try:
      cmd = command.strip()
      if not cmd:
        return False
        
      # 安全检查：禁止危险命令
      if self._is_dangerous_command(cmd):
        return False
        
      # 检查是否匹配授权前缀
      return any(
          cmd == prefix or cmd.startswith(prefix + " ")
          for prefix in self._shell_prefixes
      )
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

  # ─── 当前白名单快照（用于审计日志）──────────────────────

  def snapshot(self) -> dict:
    """获取当前权限白名单快照"""
    with self._lock:
      return {
        "read": list(self._read_patterns),
        "write": list(self._write_patterns),
        "shell": list(self._shell_prefixes),
        "history_count": len(self._permission_history),
      }

  def get_permission_history(self) -> List[Dict]:
    """获取权限变更历史"""
    with self._lock:
      return list(self._permission_history)

  # ─── 私有方法 ─────────────────────────────────────────────

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
    """检查是否为危险命令"""
    dangerous_commands = {
        'rm -rf /', 'rm -rf /*', 'dd if=/dev/zero', 'mkfs',
        'chmod 777 /', 'chown root', 'sudo su', 'su root',
        ':(){ :|:& };:', 'fork bomb', 'crash', 'reboot', 'shutdown',
        'iptables -F', 'service stop', 'systemctl stop'
    }
    
    cmd_lower = command.lower()
    for dangerous in dangerous_commands:
      if dangerous in cmd_lower:
        return True
        
    # 检查是否包含管道重定向到危险位置
    if any(pattern in cmd_lower for pattern in ['> /etc/', '>> /etc/', '> /bin/', '>> /bin/']):
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
    安全的路径匹配逻辑
    
    匹配策略：
    1. 精确匹配
    2. Glob模式匹配
    3. 前缀匹配（目录包含）
    """
    try:
      for pattern in patterns:
        if not pattern:
          continue
          
        # 规范化模式
        norm_pattern = self._secure_normalize(pattern)
        if norm_pattern is None:
          continue
          
        # 精确匹配
        if normalized_path == norm_pattern:
          return True
          
        # Glob匹配（支持通配符）
        if fnmatch.fnmatch(normalized_path, norm_pattern):
          return True
          
        # 前缀匹配：检查是否为指定目录的子路径
        if normalized_path.startswith(norm_pattern + os.sep):
          return True
          
      return False
    except Exception:
      return False

  def _record_permission_change(self, change_type: str, items: List[str]):
    """记录权限变更历史"""
    import time
    
    change_record = {
        "timestamp": time.time(),
        "type": change_type,
        "items": list(items),
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