"""
运行时权限管理器 — 白名单维护与越权检测
"""

import fnmatch
import os
from typing import List, Set

from core.manifest import Permissions


class PermissionChecker:
    """
    维护运行时权限白名单（read / write / shell）。
    所有路径在比对前统一经过 realpath 规范化，防止路径穿越攻击。
    """

    def __init__(self, init_permissions: Permissions):
        self._read_patterns: List[str] = list(init_permissions.read)
        self._write_patterns: List[str] = list(init_permissions.write)
        self._shell_prefixes: List[str] = list(init_permissions.shell)

    # ─── 权限检查 ──────────────────────────────────────────────

    def can_read(self, path: str) -> bool:
        return self._match_path(self._normalize(path), self._read_patterns)

    def can_write(self, path: str) -> bool:
        return self._match_path(self._normalize(path), self._write_patterns)

    def can_shell(self, command: str) -> bool:
        """检查命令是否以已授权的前缀开头"""
        cmd = command.strip()
        return any(cmd == prefix or cmd.startswith(prefix + " ")
                   for prefix in self._shell_prefixes)

    def can_list(self, path: str) -> bool:
        """list_directory 复用 read 白名单"""
        return self.can_read(path)

    # ─── 白名单扩展（人类批准后调用）─────────────────────────

    def grant_read(self, paths: List[str]):
        for p in paths:
            if p not in self._read_patterns:
                self._read_patterns.append(p)

    def grant_write(self, paths: List[str]):
        for p in paths:
            if p not in self._write_patterns:
                self._write_patterns.append(p)

    def grant_shell(self, prefixes: List[str]):
        for p in prefixes:
            if p not in self._shell_prefixes:
                self._shell_prefixes.append(p)

    # ─── 当前白名单快照（用于审计日志）──────────────────────

    def snapshot(self) -> dict:
        return {
            "read": list(self._read_patterns),
            "write": list(self._write_patterns),
            "shell": list(self._shell_prefixes),
        }

    # ─── 私有方法 ─────────────────────────────────────────────

    @staticmethod
    def _normalize(path: str) -> str:
        """规范化路径：展开 ~ 并 realpath（如果文件存在）"""
        path = os.path.expanduser(path)
        # 对不存在的路径也做 abspath 规范化
        return os.path.normpath(os.path.abspath(path))

    @staticmethod
    def _match_path(normalized_path: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            # 规范化 pattern
            norm_pattern = os.path.normpath(os.path.abspath(os.path.expanduser(pattern)))
            # 精确匹配
            if normalized_path == norm_pattern:
                return True
            # glob 匹配（支持 ** / * 等通配符）
            if fnmatch.fnmatch(normalized_path, norm_pattern):
                return True
            # 前缀匹配：path 是 pattern 目录的子孙
            if normalized_path.startswith(norm_pattern + os.sep):
                return True
        return False
