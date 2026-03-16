"""
原子工具集（Tool Catalog）v3.3

修复内容：
  P0-2: FindSymbolTool 只对根目录做一次权限检查，
        导致 Agent 可通过 find_symbol 读取任意未授权文件。
        → 遍历每个文件前单独调用 _check() 验证读权限。
  P2-4: AskHumanTool 使用裸 input()，GUI 模式下 stdin 已被重定向会卡死。
        → 通过注入的 input_fn 调用（与 shell._safe_input 对齐）。
"""
import ast
import base64
import difflib
import glob as glob_module
import importlib
import inspect
import json
import os
import shlex
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Dict, Optional, List, Type

import mss
import pyautogui
from PIL import Image, ImageDraw

from brtech_cva.core.config import cva_settings


# ─── 工具返回值规范 ──────────────────────────────────────────

def ok(data: Any) -> Dict:
  return {"status": "ok", "data": data}


def err(code: str, message: str) -> Dict:
  return {"status": "error", "error_code": code, "message": message}


# ─── 工具基类 ────────────────────────────────────────────────

class Tool(ABC):
  name: str = ""
  description: str = ""
  input_schema: Dict = {}

  def __init__(self, check_fn: Callable, input_fn: Optional[Callable] = None):
    self._check = check_fn
    self._input_fn = input_fn or input

  def _ctx(self, kwargs: dict) -> str:
    return kwargs.get("_context_summary", "")

  def _secure_path(self, path: str) -> Optional[str]:
    try:
      if not path:
        return None
      expanded = os.path.expanduser(path)
      abs_path = os.path.abspath(expanded)
      norm_path = os.path.normpath(abs_path)
      if any(char in norm_path for char in ['\x00', '\n', '\r']):
        return None
      return norm_path
    except (ValueError, OSError):
      return None

  @abstractmethod
  def execute(self, **kwargs) -> Dict:
    pass

  def to_api_spec(self) -> Dict:
    return {
      "name": self.name,
      "description": self.description,
      "input_schema": self.input_schema,
    }


class ToolLoader:
  """负责工具的自动发现、校验与热加载"""

  @staticmethod
  def get_custom_tools_dir() -> str:
    custom_dir = os.path.join(cva_settings.agent_dir, "custom_tools")
    os.makedirs(custom_dir, exist_ok=True)
    return custom_dir

  @classmethod
  def _get_builtin_tool_classes(cls) -> Dict[str, Type[Tool]]:
    """利用 inspect 自动扫描当前模块中所有定义的工具类"""
    builtin_tools = {}
    # 获取当前模块的所有成员
    current_module = sys.modules[__name__]
    for name, obj in inspect.getmembers(current_module):
      # 筛选条件：是类、继承自 Tool、不是 Tool 基类本身、不是抽象类
      if (inspect.isclass(obj) and
          issubclass(obj, Tool) and
          obj is not Tool and
          not inspect.isabstract(obj)):

        tool_name = getattr(obj, "name", "")
        if tool_name:
          builtin_tools[tool_name] = obj
    return builtin_tools

  @classmethod
  def verify_and_load_single(cls, file_path: str, check_fn: Callable, input_fn: Callable) -> Tool:
    """热加载单个外部工具文件并返回实例"""
    try:
      with open(file_path, 'r', encoding='utf-8') as f:
        ast.parse(f.read())

      module_name = f"dynamic_tool_{os.path.basename(file_path)[:-3]}"
      spec = importlib.util.spec_from_file_location(module_name, file_path)
      if spec is None or spec.loader is None:
        raise ImportError(f"无法加载模块定义: {file_path}")

      mod = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(mod)

      for name, obj in inspect.getmembers(mod):
        if inspect.isclass(obj) and issubclass(obj, Tool) and obj is not Tool:
          return obj(check_fn, input_fn)

      raise ValueError("未找到合法的 Tool 类")
    except Exception as e:
      raise RuntimeError(f"工具热加载失败: {e}")

  @classmethod
  def load_all(cls, capabilities: List[str], check_fn: Callable, input_fn: Callable) -> Dict[str, Tool]:
    """全自动加载：扫描内置 + 扫描自定义目录"""
    active_tools: Dict[str, Tool] = {}

    # 1. 自动扫描内置工具
    builtin_classes = cls._get_builtin_tool_classes()
    for cap in capabilities:
      if cap in builtin_classes:
        tool_class = builtin_classes[cap]
        # 特殊处理 SynthesizeTool，因为它需要传入 active_tools 的引用
        if tool_class is SynthesizeTool:
          active_tools[cap] = tool_class(check_fn, input_fn, active_tools)
        else:
          active_tools[cap] = tool_class(check_fn, input_fn)

    # 2. 自动扫描自定义目录
    custom_dir = cls.get_custom_tools_dir()
    if os.path.exists(custom_dir):
      for filename in os.listdir(custom_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
          try:
            inst = cls.verify_and_load_single(os.path.join(custom_dir, filename), check_fn, input_fn)
            # 自定义工具如果不在初始 capabilities 里，通常也允许加载（进化结果）
            active_tools[inst.name] = inst
          except Exception as e:
            print(f"⚠️  加载自定义工具 {filename} 失败: {e}")

    return active_tools


# ─── 具体工具实现 ─────────────────────────────────────────────

class FindSymbolTool(Tool):
  name = "find_symbol"
  description = "【全屏搜索】在整个项目中定位某个类或函数的定义位置。当你看到一个调用却不知道它在哪个文件时必用。"
  input_schema = {
    "type": "object",
    "properties": {
      "symbol_name": {"type": "string", "description": "类名或函数名"},
      "reason": {"type": "string"}
    },
    "required": ["symbol_name"]
  }

  def execute(self, symbol_name: str, reason: str = "", **kwargs) -> Dict:
    """
    修复 P0-2：原来只对根目录 "." 做一次权限检查，然后无限制地读取所有文件。
    现在对每个候选文件单独调用 _check()，只读取有权限的文件。
    """
    import re
    pattern = re.compile(
        rf'^\s*(?:class|def|function|func|async\s+function)\s+{re.escape(symbol_name)}\b',
        re.MULTILINE
    )
    results = []
    ctx = self._ctx(kwargs)

    for root, dirs, files in os.walk(""):
      dirs[:] = [d for d in dirs if not d.startswith(
          tuple(cva_settings.tool_settings.find_symbol_skip_start_with)
      )]
      for file in files:
        if not file.endswith(tuple(cva_settings.tool_settings.find_symbol_skip_end_with)):
          continue

        path = os.path.join(root, file)

        # 修复：对每个文件单独做权限检查，而非只检查根目录一次
        allowed, _ = self._check(self.name, path, "read", reason, ctx)
        if not allowed:
          continue

        try:
          with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if pattern.search(content):
              results.append({"path": path, "type": "definition"})
        except OSError:
          continue

    return ok({"symbol": symbol_name, "found_in": results})


class GetProjectSummaryTool(Tool):
  name = "get_project_summary"
  description = "【总览神器】一次性获取整个项目的目录结构和关键文件摘要（文件名、类型、大小、行数）。比多次调用 list_directory 更省 Token。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "根目录", "default": "."},
      "max_depth": {"type": "integer", "description": "最大递归深度（0表示只当前目录，1表示当前目录及下一层）", "default": 3},
      "reason": {"type": "string"}
    },
    "required": []
  }

  def execute(self, path: str = ".", max_depth: int = 3, reason: str = "", **kwargs) -> Dict:
    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

    allowed, msg = self._check(self.name, real_path, "list", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    if not os.path.exists(real_path):
      return err("NOT_FOUND", f"路径不存在: {path}")
    if not os.path.isdir(real_path):
      return err("NOT_A_DIRECTORY", f"不是目录: {path}")

    summary_items = []

    def walk_and_summarize(current_dir_path, current_depth):
      if current_depth > max_depth:
        return
      try:
        for entry in sorted(os.scandir(current_dir_path), key=lambda e: e.name):
          if entry.name.startswith(tuple(cva_settings.tool_settings.project_summary_skip_files)):
            continue
          full_entry_path = entry.path
          item = {
            "name": entry.name,
            "type": "dir" if entry.is_dir() else "file",
            "path": full_entry_path
          }
          if entry.is_file():
            try:
              item["fileSize"] = os.path.getsize(full_entry_path)
              with open(full_entry_path, 'rb') as fb:
                is_binary = b'\x00' in fb.read(8192)
              if is_binary:
                item["fileLines"] = 0
              else:
                try:
                  with open(full_entry_path, 'r', encoding='utf-8', errors='strict') as f:
                    item["fileLines"] = sum(1 for _ in f)
                except (UnicodeDecodeError, ValueError):
                  item["fileLines"] = 0
            except OSError:
              item["fileSize"] = 0
              item["fileLines"] = 0
          summary_items.append(item)
          if entry.is_dir():
            walk_and_summarize(full_entry_path, current_depth + 1)
      except PermissionError:
        return
      except Exception:
        return

    walk_and_summarize(real_path, 0)
    return ok({"summary_items": summary_items})


class GetFileSkeletonTool(Tool):
  name = "get_file_skeleton"
  description = "【省Token神器】只提取 Python 文件的类名、方法名及签名，不读取函数体。在了解代码结构时必用。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "文件路径"},
      "reason": {"type": "string"}
    },
    "required": ["path"]
  }

  def execute(self, path: str, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

    ext = os.path.splitext(real_path)[1].lower()
    try:
      with open(real_path, "r", encoding="utf-8") as f:
        source = f.read()
      if ext == ".py":
        return ok({"path": path, "skeleton": self._get_python_skeleton(source)})
      else:
        return ok({"path": path, "skeleton": self._get_generic_skeleton(source)})
    except Exception as e:
      return err("PARSE_ERROR", str(e))

  def _get_python_skeleton(self, source: str) -> str:
    import ast
    tree = ast.parse(source)
    skeleton = []
    imports = []
    for node in ast.iter_child_nodes(tree):
      if isinstance(node, ast.Import):
        for alias in node.names:
          imports.append(f"import {alias.name}")
      elif isinstance(node, ast.ImportFrom):
        imports.append(f"from {node.module} import {', '.join([n.name for n in node.names])}")
    if imports:
      skeleton.append("### Dependencies\n" + "\n".join(imports))
    for node in ast.iter_child_nodes(tree):
      if isinstance(node, ast.ClassDef):
        bases = [ast.unparse(b) for b in node.bases]
        base_str = f"({', '.join(bases)})" if bases else ""
        methods = [f"  def {m.name}(...): ..." for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
        skeleton.append(f"class {node.name}{base_str}:\n" + "\n".join(methods))
      elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        skeleton.append(f"def {node.name}(...): ...")
    return "\n\n".join(skeleton)

  def _get_generic_skeleton(self, source: str) -> str:
    import re
    pattern = re.compile(r'^ *(?:export +)?(?:class|function|def|async +function|public|private|static) +([a-zA-Z_][a-zA-Z0-9_]*)', re.MULTILINE)
    matches = pattern.findall(source)
    return "\n".join([f"{m} ..." for m in matches])


class ListDirectoryTool(Tool):
  name = "list_directory"
  description = "列出指定目录下的文件和子目录。返回名称、类型（file/dir）及大小信息。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "目录路径"},
      "reason": {"type": "string", "description": "访问原因（用于越权申请）"},
    },
    "required": ["path"],
  }

  def execute(self, path: str, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "list", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")
    if not os.path.exists(real_path):
      return err("NOT_FOUND", f"路径不存在: {path}")
    if not os.path.isdir(real_path):
      return err("NOT_A_DIRECTORY", f"不是目录: {path}")

    try:
      entries = []
      for name in sorted(os.listdir(real_path)):
        full = os.path.join(real_path, name)
        try:
          stat = os.stat(full, follow_symlinks=False)
          entries.append({
            "name": name,
            "type": "dir" if os.path.isdir(full) else "file",
            "size": stat.st_size,
            "path": full,
            "is_symlink": os.path.islink(full),
          })
        except (OSError, PermissionError):
          continue
      return ok({"path": real_path, "entries": entries, "count": len(entries)})
    except PermissionError as e:
      return err("OS_PERMISSION_DENIED", str(e))


class ReadFileTool(Tool):
  name = "read_file"
  description = "读取文件内容。支持行范围读取以节省 Token。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "文件路径"},
      "reason": {"type": "string", "description": "读取原因"},
      "start_line": {"type": "integer", "description": "起始行 (从1开始)", "default": 1},
      "end_line": {"type": "integer", "description": "结束行"},
      "encoding": {"type": "string", "default": "utf-8"}
    },
    "required": ["path", "reason"],
  }

  MAX_PHYSICAL_FILE_SIZE = cva_settings.tool_settings.read_max_physical_file_size
  MAX_RETURNED_CONTENT_CHARS = cva_settings.tool_settings.read_max_returned_content_chars

  def execute(self, path: str, start_line: int = 1, end_line: Optional[int] = None,
      encoding: str = "utf-8", reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None or not os.path.exists(real_path):
      return err("NOT_FOUND", "文件不存在")

    try:
      if os.path.getsize(real_path) > self.MAX_PHYSICAL_FILE_SIZE:
        return err("FILE_TOO_LARGE", f"文件超过 {self.MAX_PHYSICAL_FILE_SIZE / (1024 * 1024)}MB，请先用搜索或大纲工具查看")

      with open(real_path, "r", encoding=encoding, errors="replace") as f:
        lines = f.readlines()

      total_lines = len(lines)
      effective_end = end_line if end_line else total_lines
      start_idx = max(0, start_line - 1)
      end_idx = min(total_lines, effective_end)
      content = "".join(lines[start_idx:end_idx])

      if len(content) > self.MAX_RETURNED_CONTENT_CHARS:
        content = content[:self.MAX_RETURNED_CONTENT_CHARS] + f"\n... (内容已截断，共 {len(content)} 字符，仅返回前 {self.MAX_RETURNED_CONTENT_CHARS} 字符以节省Token)"

      return ok({
        "artifact_type": "file_content",
        "metadata": {
          "path": real_path,
          "range": f"{start_idx + 1}-{end_idx}",
          "total_lines": total_lines,
          "is_full_text": (start_idx == 0 and end_idx == total_lines) and (len(content) <= self.MAX_RETURNED_CONTENT_CHARS),
        },
        "content": content,
        "can_dehydrate": True
      })
    except Exception as e:
      return err("IO_ERROR", str(e))


class BackupFileTool(Tool):
  name = "backup_file"
  description = "为指定文件创建带有时间戳的备份副本。建议在执行 write_file 等破坏性操作前调用。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "要备份的文件路径"},
      "reason": {"type": "string", "description": "备份原因"},
    },
    "required": ["path"],
  }

  def execute(self, path: str, reason: str = "破坏性修改前的自动备份", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")
    if not os.path.exists(real_path):
      return err("NOT_FOUND", f"源文件不存在: {path}")
    if os.path.isdir(real_path):
      return err("IS_A_DIRECTORY", f"路径是目录，无法直接备份: {path}")

    try:
      import datetime
      import shutil
      base, ext = os.path.splitext(real_path)
      timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
      backup_path = f"{base}-{timestamp}{ext}"
      shutil.copy2(real_path, backup_path)
      return ok({
        "original_path": real_path,
        "backup_path": backup_path,
        "timestamp": timestamp,
        "size": os.path.getsize(backup_path)
      })
    except Exception as e:
      return err("BACKUP_ERROR", f"备份失败: {str(e)}")


class WriteFileTool(Tool):
  name = "write_file"
  description = "将内容写入文件（覆盖写）。目标目录不存在时自动创建。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "目标文件路径"},
      "content": {"type": "string", "description": "写入内容"},
      "encoding": {"type": "string", "description": "字符编码（默认 utf-8）"},
      "reason": {"type": "string"},
    },
    "required": ["path", "content"],
  }

  MAX_CONTENT_SIZE = cva_settings.tool_settings.write_max_content_size

  def execute(self, path: str, content: str, encoding: str = "utf-8", reason: str = "", **kwargs) -> Dict:
    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

    old_content = ""
    diff_str = None
    if real_path and os.path.exists(real_path):
      try:
        with open(real_path, 'r', encoding=encoding, errors='replace') as f:
          old_content = f.read()

        # 生成统一差异文本（用于日志或控制台）
        diff = difflib.unified_diff(
            old_content.splitlines(keepends=True),
            content.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=3
        )
        diff_str = "".join(diff)
      except Exception:
        diff_str = "[无法生成差异预览]"
    else:
      diff_str = f"[新文件创建] 内容长度: {len(content)} 字符"

    allowed, msg = self._check(self.name, path, "write", reason, self._ctx(kwargs), diff=diff_str, diff_data=(old_content, content))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    content_bytes = content.encode(encoding)
    if len(content_bytes) > self.MAX_CONTENT_SIZE:
      return err("CONTENT_TOO_LARGE", f"内容过大超过 {self.MAX_CONTENT_SIZE // (1024 * 1024)}MB 限制")

    try:
      dir_path = os.path.dirname(real_path) or "."
      os.makedirs(dir_path, exist_ok=True)
      temp_path = real_path + f".tmp.{int(time.time())}"
      try:
        with open(temp_path, "w", encoding=encoding) as f:
          f.write(content)
        os.rename(temp_path, real_path)
      except Exception:
        if os.path.exists(temp_path):
          try:
            os.remove(temp_path)
          except OSError:
            pass
        raise
      return ok({"path": real_path, "bytes_written": len(content_bytes)})
    except OSError as e:
      return err("IO_ERROR", str(e))


class AppendFileTool(Tool):
  name = "append_file"
  description = "将内容追加写入文件末尾。文件不存在时自动创建。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string"},
      "content": {"type": "string"},
      "reason": {"type": "string"},
    },
    "required": ["path", "content"],
  }

  MAX_APPEND_SIZE = cva_settings.tool_settings.append_max_append_size

  def execute(self, path: str, content: str, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "write", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

    content_bytes = content.encode('utf-8')
    if len(content_bytes) > self.MAX_APPEND_SIZE:
      return err("CONTENT_TOO_LARGE", f"追加内容过大")

    try:
      dir_path = os.path.dirname(real_path) or "."
      os.makedirs(dir_path, exist_ok=True)
      with open(real_path, "a", encoding="utf-8") as f:
        f.write(content)
      return ok({"path": real_path, "bytes_appended": len(content_bytes)})
    except OSError as e:
      return err("IO_ERROR", str(e))


class RunShellTool(Tool):
  name = "run_shell"
  description = "在系统 Shell 中执行命令，返回 stdout、stderr 和退出码。"
  input_schema = {
    "type": "object",
    "properties": {
      "command": {"type": "string", "description": "要执行的命令"},
      "timeout": {"type": "integer", "description": "超时秒数（默认 30）"},
      "cwd": {"type": "string", "description": "工作目录（可选）"},
      "reason": {"type": "string"},
    },
    "required": ["command"],
  }

  MAX_COMMAND_LENGTH = cva_settings.tool_settings.shell_max_command_length
  MAX_ARGS_COUNT = cva_settings.tool_settings.shell_max_args_count
  MAX_TIMEOUT = cva_settings.tool_settings.shell_max_timeout

  def execute(self, command: str, timeout: int = 30, cwd: Optional[str] = None, reason: str = "", **kwargs) -> Dict | None:
    allowed, msg = self._check(self.name, command, "shell", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    try:
      args = shlex.split(command)
    except ValueError as e:
      return err("INVALID_COMMAND", f"命令格式错误: {e}")

    if len(command) > self.MAX_COMMAND_LENGTH:
      return err("COMMAND_TOO_LONG", "命令过长")
    if len(args) > self.MAX_ARGS_COUNT:
      return err("TOO_MANY_ARGS", f"参数过多")

    if cwd:
      real_cwd = self._secure_path(cwd)
      if real_cwd is None or not os.path.exists(real_cwd) or not os.path.isdir(real_cwd):
        return err("INVALID_CWD", f"无效的工作目录: {cwd}")
      cwd = real_cwd

    timeout = min(timeout, self.MAX_TIMEOUT)
    max_retries = 2
    for attempt in range(max_retries + 1):
      try:
        result = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env={
              'PATH': os.environ.get('PATH', ''),
              'HOME': os.environ.get('HOME', ''),
              'USER': os.environ.get('USER', ''),
              'LANG': os.environ.get('LANG', 'en_US.UTF-8'),
            }
        )
        return ok({
          "stdout": result.stdout,
          "stderr": result.stderr,
          "returncode": result.returncode,
          "command": command,
          "args": args,
        })
      except subprocess.TimeoutExpired:
        return err("TIMEOUT", f"命令超时（{timeout}s）")
      except FileNotFoundError:
        return err("COMMAND_NOT_FOUND", f"命令不存在: {args[0]}")
      except PermissionError:
        return err("PERMISSION_DENIED", f"权限不足")
      except Exception as e:
        if attempt == max_retries:
          return err("EXEC_ERROR", f"执行失败: {str(e)}")
        time.sleep(0.1 * (attempt + 1))
    return None


class AskHumanTool(Tool):
  name = "ask_human"
  description = "向人类导师提问，挂起当前任务等待文字回复。"
  input_schema = {
    "type": "object",
    "properties": {
      "question": {"type": "string", "description": "向人类提出的问题"},
      "context": {"type": "string", "description": "问题背景"},
    },
    "required": ["question"],
  }

  def execute(self, question: str, context: str = "", **_) -> Dict:
    """
    修复 P2-4：使用 self._input_fn 替代裸 input()。
    GUI 模式下 _input_fn 由 build_tools() 注入 shell._safe_input，
    CLI 模式下默认使用内置 input()，行为与修复前完全一致。
    """
    print("\n" + "─" * 60)
    print("💬 [CVA 向您提问]")
    if context:
      print(f"   背景: {context}")
    print(f"   问题: {question}")
    print("─" * 60)
    try:
      answer = self._input_fn("   您的回答: ")
      if isinstance(answer, str):
        answer = answer.strip()
      print("─" * 60 + "\n")
      return ok({"answer": answer})
    except EOFError:
      return err("NO_INPUT", "未获得输入")
    except KeyboardInterrupt:
      return err("INTERRUPTED", "中断")


class SearchFilesTool(Tool):
  name = "search_files"
  description = "在指定目录内搜索匹配模式的文件名或文件内容。"
  input_schema = {
    "type": "object",
    "properties": {
      "pattern": {"type": "string", "description": "搜索模式"},
      "path": {"type": "string", "description": "根目录"},
      "search_content": {"type": "boolean", "description": "是否搜内容"},
      "reason": {"type": "string"},
    },
    "required": ["pattern"],
  }

  MAX_MATCHES = cva_settings.tool_settings.search_max_matches
  MAX_FILE_SIZE = cva_settings.tool_settings.search_max_file_size
  PROGRESS_INTERVAL = cva_settings.tool_settings.progress_interval

  def execute(self, pattern: str, path: str = ".", search_content: bool = False, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None or not os.path.exists(real_path):
      return err("INVALID_PATH", f"路径不存在: {path}")

    try:
      matches = []
      if not search_content:
        for fpath in glob_module.glob(os.path.join(real_path, "**", f"*{pattern}*"), recursive=True):
          if self._is_safe_path(fpath, real_path):
            matches.append({"path": fpath, "type": "filename"})
            if len(matches) >= self.MAX_MATCHES:
              break
      else:
        file_count = 0
        for root, dirs, files in os.walk(real_path):
          if not self._is_safe_path(root, real_path):
            dirs.clear()
            continue
          for fname in files:
            fpath = os.path.join(root, fname)
            if not self._is_safe_path(fpath, real_path):
              continue
            file_count += 1
            if file_count % self.PROGRESS_INTERVAL == 0:
              print(f"[搜索] 已处理 {file_count} 个文件，找到 {len(matches)} 个匹配...")
            try:
              if os.path.getsize(fpath) > self.MAX_FILE_SIZE:
                continue
              with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                  if pattern.lower() in line.lower():
                    matches.append({"path": fpath, "line": i, "content": line.rstrip()[:200], "type": "content"})
                    if len(matches) >= self.MAX_MATCHES:
                      break
            except (OSError, UnicodeDecodeError):
              continue
            if len(matches) >= self.MAX_MATCHES:
              break
        print(f"[搜索] 完成！共处理 {file_count} 个文件，找到 {len(matches)} 个匹配")

      return ok({"matches": matches[:self.MAX_MATCHES], "count": len(matches), "pattern": pattern})
    except Exception as e:
      return err("SEARCH_ERROR", str(e))

  def _is_safe_path(self, path: str, base_path: str) -> bool:
    try:
      real_path = os.path.realpath(path)
      real_base = os.path.realpath(base_path)
      return real_path.startswith(real_base + os.sep) or real_path == real_base
    except Exception:
      return False


class HttpRequestTool(Tool):
  name = "http_request"
  description = "发起 HTTP 请求。目标域名须在白名单中注册。"
  input_schema = {
    "type": "object",
    "properties": {
      "url": {"type": "string"},
      "method": {"type": "string"},
      "headers": {"type": "object"},
      "body": {"type": "string"},
      "timeout": {"type": "integer"},
      "reason": {"type": "string"},
    },
    "required": ["url", "method"],
  }

  MAX_TIMEOUT = cva_settings.tool_settings.max_timeout
  MAX_BODY_SIZE = cva_settings.tool_settings.max_body_size

  def execute(self, url: str, method: str = "GET", headers: dict = None,
      body: str = None, timeout: int = 15, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, url, "shell", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    import urllib.request
    import urllib.error

    if body and len(body) > self.MAX_BODY_SIZE:
      return err("BODY_TOO_LARGE", f"请求体过大，限制 {self.MAX_BODY_SIZE} 字节")

    try:
      req = urllib.request.Request(url, method=method.upper(), headers=headers or {}, data=body.encode() if body else None)
      with urllib.request.urlopen(req, timeout=min(timeout, self.MAX_TIMEOUT)) as resp:
        return ok({"status_code": resp.status, "body": resp.read().decode("utf-8", errors="replace")[:10000]})
    except urllib.error.HTTPError as e:
      return err("HTTP_ERROR", f"HTTP错误: {e.code} {e.reason}")
    except urllib.error.URLError as e:
      return err("URL_ERROR", f"URL错误: {e.reason}")
    except Exception as e:
      return err("HTTP_ERROR", str(e))


class SubmitPlanTool(Tool):
  name = "submit_plan"
  description = "提交或更新你的行动计划。在执行复杂任务前必用。系统会记录该计划并用于后续进度审计。"
  input_schema = {
    "type": "object",
    "properties": {
      "goal": {"type": "string", "description": "最终目标"},
      "milestones": {"type": "array", "items": {"type": "string"}, "description": "关键步骤分解"},
      "strategy": {"type": "string", "description": "采用的策略"}
    },
    "required": ["goal", "milestones"]
  }

  def execute(self, goal: str, milestones: list, strategy: str = "", **kwargs) -> Dict:
    return ok({
      "status": "PLAN_ACCEPTED",
      "message": "计划已备案。请开始按计划执行，并在遇到重大阻碍时更新计划。",
      "current_goal": goal
    })


class ExecutePythonScriptTool(Tool):
  name = "execute_python_script"
  description = "【高阶工具】在受控环境中执行一段 Python 代码。适合处理大批量文件、复杂逻辑计算或自定义数据分析。"
  input_schema = {
    "type": "object",
    "properties": {
      "script": {"type": "string", "description": "完整的 Python 代码字符串"},
      "reason": {"type": "string", "description": "执行该脚本的目的"}
    },
    "required": ["script"]
  }

  def execute(self, script: str, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, "python3", "shell", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as tmp:
      tmp.write(script)
      tmp_path = tmp.name

    try:
      result = subprocess.run(
          [sys.executable, tmp_path],
          capture_output=True, text=True, timeout=60
      )
      return ok({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode
      })
    except Exception as e:
      return err("EXECUTION_ERROR", str(e))
    finally:
      if os.path.exists(tmp_path):
        os.remove(tmp_path)


class GetRepoMapTool(Tool):
  name = "get_repo_map"
  description = "【项目语义地图】利用系统级 ctags 引擎生成整个项目的符号索引。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "起始目录", "default": "."},
      "reason": {"type": "string", "description": "调用原因"}
    }
  }

  def execute(self, path: str = ".", reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if not real_path or not os.path.exists(real_path):
      return err("INVALID_PATH", f"路径不存在: {path}")

    cmd = cva_settings.tool_settings.repo_map_cmd + [real_path]
    try:
      result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
      if result.returncode != 0:
        return err("CTAGS_ERROR", result.stderr or "未知 ctags 错误")

      tags_by_file = {}
      for line in result.stdout.splitlines():
        if not line.strip():
          continue
        try:
          tag = json.loads(line)
          fpath = tag.get("path")
          if not fpath:
            continue
          if fpath not in tags_by_file:
            tags_by_file[fpath] = []
          tags_by_file[fpath].append(tag)
        except Exception:
          continue

      repo_map = []
      for fpath in sorted(tags_by_file.keys()):
        rel_fpath = os.path.relpath(fpath, real_path)
        repo_map.append(f"file: {rel_fpath}")
        tags = sorted(tags_by_file[fpath], key=lambda x: x.get("line", 0))
        for t in tags:
          kind, name, sign, line = t.get("kind"), t.get("name"), t.get("signature", ""), t.get("line", 0)
          if kind in ("variable", "local", "parameter"):
            continue
          indent = "    " if kind in ("method", "member", "field") else "  "
          repo_map.append(f"{indent}{kind} {name}{sign} [line:{line}]")
        repo_map.append("")

      final_text = "\n".join(repo_map)
      if len(final_text) > 20000:
        final_text = final_text[:20000] + "\n\n... [地图过长，已截断]"

      return ok({
        "map": final_text,
        "total_files": len(tags_by_file),
        "info": "使用 ctags 成功生成语义索引"
      })

    except FileNotFoundError:
      return err("SYSTEM_ERROR", "未找到 ctags 二进制文件。请安装 ctags (如: pacman -S ctags)")
    except Exception as e:
      return err("RUNTIME_ERROR", str(e))


class SynthesizeTool(Tool):
  name = "synthesize_tool"
  description = "【自我进化引擎】动态编写并注册新工具。代码需继承 Tool 类并实现 execute。"
  input_schema = {
    "type": "object",
    "properties": {
      "tool_name": {"type": "string"},
      "code": {"type": "string"},
      "reason": {"type": "string"}
    },
    "required": ["tool_name", "code", "reason"]
  }

  def __init__(self, check_fn: Callable, input_fn: Callable, active_tools_ref: Dict[str, Tool]):
    super().__init__(check_fn, input_fn)
    self._active_tools = active_tools_ref

  def execute(self, tool_name: str, code: str, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, tool_name, "write", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    custom_dir = ToolLoader.get_custom_tools_dir()
    file_path = os.path.join(custom_dir, f"{tool_name}.py")

    try:
      with open(file_path, "w", encoding="utf-8") as f:
        f.write(code)

      # 联动 ToolLoader 进行单文件热加载
      new_inst = ToolLoader.verify_and_load_single(file_path, self._check, self._input_fn)

      # 实时注入工具池
      self._active_tools[new_inst.name] = new_inst

      return ok({"message": f"工具 {new_inst.name} 已合成并即时加载。"})
    except Exception as e:
      if os.path.exists(file_path):
        os.remove(file_path)
      return err("SYNTHESIZE_FAILED", str(e))


class ScreenshotTool(Tool):
  name = "take_screenshot"
  description = "获取当前屏幕截图。用于在操作前观察环境，或在操作后确认状态。"

  def execute(self, reason: str = "观察屏幕状态", **kwargs):
    # 将截图逻辑抽离出来，方便复用
    return self._do_screenshot(reason, **kwargs)

  def _do_screenshot(self, reason: str, **kwargs):
    allowed, msg = self._check(self.name, "screenshot", "gui_control", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    try:
      mx, my = pyautogui.position()
      with mss.mss() as sct:
        target_monitor = sct.monitors[1]
        for m in sct.monitors[1:]:
          if m['left'] <= mx <= m['left'] + m['width'] and \
              m['top'] <= my <= m['top'] + m['height']:
            target_monitor = m
            break

        sct_img = sct.grab(target_monitor)
        img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")

        # 绘制鼠标位置
        rx, ry = mx - target_monitor['left'], my - target_monitor['top']
        draw = ImageDraw.Draw(img)
        radius = 12
        draw.ellipse((rx - radius, ry - radius, rx + radius, ry + radius), fill="red", outline="white", width=2)

        # 缩放以节省 Token
        sw, sh = img.size
        max_side = 1024
        if sw > sh:
          new_w, new_h = max_side, int(sh * (max_side / sw))
        else:
          new_h, new_w = max_side, int(sw * (max_side / sh))
        resized_img = img.resize((new_w, new_h), Image.Resampling.LANCZOS)

        timestamp = int(time.time())
        save_path = Path(f"var/artifacts/screenshot_{timestamp}.jpg")
        save_path.parent.mkdir(parents=True, exist_ok=True)
        resized_img.save(save_path, "JPEG", quality=85)

        buffered = BytesIO()
        resized_img.save(buffered, format="JPEG", quality=85)
        img_str = base64.b64encode(buffered.getvalue()).decode()

        return {
          "status": "ok",
          "data": {
            "artifact_type": "image",
            "path": str(save_path),
            "base64": img_str,
            "viewport": [new_w, new_h],
            "coordinate_system": "0-1000",
            "message": "已获取当前屏幕状态，请根据此图判断操作是否成功。"
          }
        }
    except Exception as e:
      return err("SCREENSHOT_ERROR", str(e))


class ComputerControlTool(Tool):
  """
  原始的多合一控制工具，保留作为兼容入口。
  GLM-4 等 function calling 能力较弱的模型请改用拆分后的专用工具：
    mouse_click / mouse_double_click / keyboard_type / keyboard_key / mouse_scroll
  """
  name = "computer_control"
  description = (
    "控制鼠标和键盘。注意：本工具在执行动作后会【自动返回一张操作后的截图】。"
    "你必须通过这张截图确认你的动作（如打开浏览器、点击按钮）是否产生了预期的 UI 变化。"
    "如果截图显示没有变化，说明操作失败，请尝试其他方法（如改用鼠标点击而非快捷键）。"
  )
  input_schema = {
    "type": "object",
    "properties": {
      "action": {
        "type": "string",
        "enum": ["move", "click", "double_click", "right_click", "type", "key", "scroll"],
        "description": "动作类型"
      },
      "x": {"type": "integer", "description": "归一化横坐标 (0-1000)"},
      "y": {"type": "integer", "description": "归一化纵坐标 (0-1000)"},
      "text": {"type": "string", "description": "输入文本"},
      "key": {"type": "string", "description": "按键名 (如 'enter', 'meta+t', 'backspace')"},
      "wait_ms": {"type": "integer", "description": "动作执行后等待多少毫秒再截图确认 (默认 500ms，打开应用建议 2000ms)", "default": 500},
      "reason": {"type": "string", "description": "操作原因及预期结果"}
    },
    "required": ["action", "reason"]
  }

  def execute(self, action: str, x: int = None, y: int = None, text: str = None,
      key: str = None, wait_ms: int = 500, reason: str = "", **kwargs):

    target_desc = f"{action}(x={x}, y={y}, text={text}, key={key})"
    allowed, msg = self._check(self.name, target_desc, "gui_control", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    try:
      pyautogui.PAUSE = 0.1
      mx, my = pyautogui.position()
      real_x, real_y = mx, my

      with mss.mss() as sct:
        target_monitor = sct.monitors[1]
        for m in sct.monitors[1:]:
          if m['left'] <= mx <= m['left'] + m['width'] and \
              m['top'] <= my <= m['top'] + m['height']:
            target_monitor = m
            break

        if x is not None and y is not None:
          real_x = target_monitor['left'] + int((x / 1000.0) * target_monitor['width'])
          real_y = target_monitor['top'] + int((y / 1000.0) * target_monitor['height'])
          real_x = max(target_monitor['left'], min(target_monitor['left'] + target_monitor['width'] - 1, real_x))
          real_y = max(target_monitor['top'], min(target_monitor['top'] + target_monitor['height'] - 1, real_y))

      if action == "move":
        pyautogui.moveTo(real_x, real_y, duration=0.2)
      elif action == "click":
        pyautogui.click(real_x, real_y)
      elif action == "double_click":
        pyautogui.doubleClick(real_x, real_y)
      elif action == "right_click":
        pyautogui.rightClick(real_x, real_y)
      elif action == "type":
        pyautogui.write(text, interval=0.05)
      elif action == "key":
        k = key.lower() if key else ""
        if k == "return":
          k = "enter"
        pyautogui.press(k)
      elif action == "scroll":
        pyautogui.scroll(x if x is not None else -10)

      time.sleep(wait_ms / 1000.0)

      scr_tool = ScreenshotTool(self._check, self._input_fn)
      scr_result = scr_tool._do_screenshot(reason=f"确认动作结果: {target_desc}")

      if scr_result["status"] == "ok":
        scr_result["data"]["message"] = f"已执行 {action}。这是操作后的屏幕截图，请确认是否符合预期。"
        return scr_result
      else:
        return ok({"message": f"已执行 {action}，但截图失败: {scr_result.get('message')}"})

    except Exception as e:
      return err("GUI_ERROR", str(e))

  def _do_action_and_screenshot(self, action_fn, action_desc: str, wait_ms: int):
    """公共的执行+截图逻辑，供子类复用"""
    try:
      action_fn()
      time.sleep(wait_ms / 1000.0)
      scr_tool = ScreenshotTool(self._check, self._input_fn)
      scr_result = scr_tool._do_screenshot(reason=f"确认动作结果: {action_desc}")
      if scr_result["status"] == "ok":
        scr_result["data"]["message"] = f"已执行 {action_desc}。这是操作后的屏幕截图，请确认是否符合预期。"
        return scr_result
      return ok({"message": f"已执行 {action_desc}，但截图失败"})
    except Exception as e:
      return err("GUI_ERROR", str(e))

  @staticmethod
  def _map_coords(x: int, y: int):
    """把归一化坐标 (0-1000) 映射到屏幕真实像素坐标"""
    with mss.mss() as sct:
      mx, my = pyautogui.position()
      target_monitor = sct.monitors[1]
      for m in sct.monitors[1:]:
        if m['left'] <= mx <= m['left'] + m['width'] and \
            m['top'] <= my <= m['top'] + m['height']:
          target_monitor = m
          break
      real_x = target_monitor['left'] + int((x / 1000.0) * target_monitor['width'])
      real_y = target_monitor['top'] + int((y / 1000.0) * target_monitor['height'])
      real_x = max(target_monitor['left'], min(target_monitor['left'] + target_monitor['width'] - 1, real_x))
      real_y = max(target_monitor['top'], min(target_monitor['top'] + target_monitor['height'] - 1, real_y))
      return real_x, real_y


class MouseClickTool(Tool):
  """
  鼠标点击。schema 极简，只有三个字段，专为 GLM-4 等 function calling 较弱的模型设计。
  坐标使用归一化值 0-1000，0 是屏幕左/上边缘，1000 是右/下边缘。
  """
  name = "mouse_click"
  description = "鼠标左键单击指定位置。执行后自动返回屏幕截图供你确认结果。坐标范围 0-1000（归一化）。"
  input_schema = {
    "type": "object",
    "properties": {
      "x": {"type": "integer", "description": "横坐标 0-1000"},
      "y": {"type": "integer", "description": "纵坐标 0-1000"},
      "reason": {"type": "string", "description": "点击原因"}
    },
    "required": ["x", "y", "reason"]
  }

  def execute(self, x: int, y: int, reason: str = "", **kwargs):
    allowed, msg = self._check(self.name, f"click({x},{y})", "gui_control", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)
    real_x, real_y = ComputerControlTool._map_coords(x, y)
    ctrl = ComputerControlTool(self._check, self._input_fn)
    return ctrl._do_action_and_screenshot(
        lambda: pyautogui.click(real_x, real_y),
        f"click({x},{y})", 500
    )


class MouseDoubleClickTool(Tool):
  """鼠标左键双击指定位置。"""
  name = "mouse_double_click"
  description = "鼠标左键双击指定位置。执行后自动返回截图。坐标范围 0-1000（归一化）。"
  input_schema = {
    "type": "object",
    "properties": {
      "x": {"type": "integer", "description": "横坐标 0-1000"},
      "y": {"type": "integer", "description": "纵坐标 0-1000"},
      "reason": {"type": "string", "description": "双击原因"}
    },
    "required": ["x", "y", "reason"]
  }

  def execute(self, x: int, y: int, reason: str = "", **kwargs):
    allowed, msg = self._check(self.name, f"double_click({x},{y})", "gui_control", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)
    real_x, real_y = ComputerControlTool._map_coords(x, y)
    ctrl = ComputerControlTool(self._check, self._input_fn)
    return ctrl._do_action_and_screenshot(
        lambda: pyautogui.doubleClick(real_x, real_y),
        f"double_click({x},{y})", 500
    )


class KeyboardTypeTool(Tool):
  """在当前焦点位置输入文字。"""
  name = "keyboard_type"
  description = "在当前焦点输入框中输入文字。执行后自动返回截图。"
  input_schema = {
    "type": "object",
    "properties": {
      "text": {"type": "string", "description": "要输入的文字"},
      "reason": {"type": "string", "description": "输入原因"}
    },
    "required": ["text", "reason"]
  }

  def execute(self, text: str, reason: str = "", **kwargs):
    allowed, msg = self._check(self.name, f"type({text[:20]})", "gui_control", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)
    ctrl = ComputerControlTool(self._check, self._input_fn)
    return ctrl._do_action_and_screenshot(
        lambda: pyautogui.write(text, interval=0.05),
        f"type({text[:20]})", 300
    )


class KeyboardKeyTool(Tool):
  """按下快捷键或功能键。"""
  name = "keyboard_key"
  description = (
    "按下快捷键或功能键。执行后自动返回截图。"
    "常用示例：'enter'=回车, 'ctrl+t'=新标签页, 'ctrl+l'=聚焦地址栏, "
    "'ctrl+w'=关闭标签, 'f5'=刷新, 'escape'=取消, 'backspace'=退格。"
  )
  input_schema = {
    "type": "object",
    "properties": {
      "key": {"type": "string", "description": "按键名，如 'enter', 'ctrl+t', 'ctrl+l', 'f5'"},
      "reason": {"type": "string", "description": "按键原因"}
    },
    "required": ["key", "reason"]
  }

  def execute(self, key: str, reason: str = "", **kwargs):
    allowed, msg = self._check(self.name, f"key({key})", "gui_control", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)
    k = key.lower().strip()
    if k == "return":
      k = "enter"
    ctrl = ComputerControlTool(self._check, self._input_fn)
    return ctrl._do_action_and_screenshot(
        lambda: pyautogui.hotkey(*k.split('+')) if '+' in k else pyautogui.press(k),
        f"key({key})", 800
    )


class MouseScrollTool(Tool):
  """鼠标滚轮滚动。"""
  name = "mouse_scroll"
  description = "滚动鼠标滚轮。amount 为正数向上滚，负数向下滚，通常 ±3 到 ±10。执行后自动返回截图。"
  input_schema = {
    "type": "object",
    "properties": {
      "amount": {"type": "integer", "description": "滚动量，正数向上，负数向下"},
      "reason": {"type": "string", "description": "滚动原因"}
    },
    "required": ["amount", "reason"]
  }

  def execute(self, amount: int, reason: str = "", **kwargs):
    allowed, msg = self._check(self.name, f"scroll({amount})", "gui_control", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)
    ctrl = ComputerControlTool(self._check, self._input_fn)
    return ctrl._do_action_and_screenshot(
        lambda: pyautogui.scroll(amount),
        f"scroll({amount})", 300
    )


# ─── 工具注册表 ───────────────────────────────────────────────


def build_tools(capabilities: list, check_fn: Callable, input_fn: Optional[Callable] = None) -> Dict[str, Tool]:
  """
  现在 build_tools 变得极其简单，全部委托给 ToolLoader
  """
  return ToolLoader.load_all(capabilities, check_fn, input_fn or input)
