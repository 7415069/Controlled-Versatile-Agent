"""
原子工具集（Tool Catalog）v3.2 - Token优化版
优化内容：
- 搜索工具添加进度反馈
- 改进错误处理，使用更具体的异常类型
- 优化文件大小检查逻辑
- 降低默认文件读取限制：50000 -> 30000字符，节省token
"""
import glob as glob_module
import json
import os
import shlex
import subprocess
import sys
import time
from typing import Any, Callable, Dict, Optional

from core.config import cvs_settings


# ─── 工具返回值规范 ──────────────────────────────────────────

def ok(data: Any) -> Dict:
  return {"status": "ok", "data": data}


def err(code: str, message: str) -> Dict:
  return {"status": "error", "error_code": code, "message": message}


# ─── 工具基类 ────────────────────────────────────────────────

class Tool:
  name: str = ""
  description: str = ""
  input_schema: Dict = {}

  def __init__(self, check_fn: Callable):
    """
    check_fn: escalation_manager.check 的引用
    签名: check(tool_name, target, permission_type, reason, context) -> (bool, Optional[str])
    """
    self._check = check_fn

  def _ctx(self, kwargs: dict) -> str:
    """从 execute kwargs 中提取对话上下文摘要（由 shell._dispatch_tool 注入）"""
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

  def execute(self, **kwargs) -> Dict:
    raise NotImplementedError

  def to_api_spec(self) -> Dict:
    return {
      "name": self.name,
      "description": self.description,
      "input_schema": self.input_schema,
    }


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
    # 权限检查（通常允许在项目范围内搜索）
    allowed, msg = self._check(self.name, ".", "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    import re
    # 匹配 class Symbol 或 def Symbol 或 function Symbol
    pattern = re.compile(rf'^\s*(?:class|def|function|func|async\s+function)\s+{symbol_name}\b', re.MULTILINE)
    results = []

    # 遍历项目（复用之前的安全路径逻辑）
    for root, dirs, files in os.walk("."):
      # 排除干扰目录
      dirs[:] = [d for d in dirs if not d.startswith(cvs_settings.tool_settings.find_symbol_skip_start_with)]
      for file in files:
        if not file.endswith(cvs_settings.tool_settings.find_symbol_skip_end_with):
          continue

        path = os.path.join(root, file)
        try:
          with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if pattern.search(content):
              results.append({"path": path, "type": "definition"})
        except:
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
    # Fix 1: 先校验路径，再权限检查（空路径应返回 INVALID_PATH 而非 PERMISSION_DENIED）
    # Fix 2: 传规范化后的 real_path 给 _check，确保与白名单格式一致
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
        # Fix 3: sorted() 对 DirEntry 排序必须指定 key，否则抛 TypeError 被静默吞掉导致返回空列表
        for entry in sorted(os.scandir(current_dir_path), key=lambda e: e.name):
          if entry.name.startswith(cvs_settings.tool_settings.project_summary_skip_files):
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
              # 通过检测 null byte 区分二进制文件（二进制文件 fileLines=0）
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
            except Exception:
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
    ext = os.path.splitext(real_path)[1].lower()

    try:
      with open(real_path, "r", encoding="utf-8") as f:
        source = f.read()

      if ext == ".py":
        return ok({"path": path, "skeleton": self._get_python_skeleton(source)})
      else:
        # 对 C-style 语言 (JS, TS, C, Java, Go) 使用通用的正则提取
        return ok({"path": path, "skeleton": self._get_generic_skeleton(source)})
    except Exception as e:
      return err("PARSE_ERROR", str(e))

  def _get_python_skeleton(self, source: str) -> str:
    import ast
    tree = ast.parse(source)
    skeleton = []

    # ─── 新增：提取导入关系 ───
    imports = []
    for node in ast.iter_child_nodes(tree):
      if isinstance(node, ast.Import):
        for alias in node.names:
          imports.append(f"import {alias.name}")
      elif isinstance(node, ast.ImportFrom):
        imports.append(f"from {node.module} import {', '.join([n.name for n in node.names])}")

    if imports:
      skeleton.append("### Dependencies\n" + "\n".join(imports))

    # ─── 原有的类和函数提取 ───
    for node in ast.iter_child_nodes(tree):
      if isinstance(node, ast.ClassDef):
        # 记录继承关系，比如 class A(B):
        bases = [ast.unparse(b) for b in node.bases]
        base_str = f"({', '.join(bases)})" if bases else ""
        methods = [f"  def {m.name}(...): ..." for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
        skeleton.append(f"class {node.name}{base_str}:\n" + "\n".join(methods))
      elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        skeleton.append(f"def {node.name}(...): ...")

    return "\n\n".join(skeleton)

  def _get_generic_skeleton(self, source: str) -> str:
    """基于正则的通用大纲提取（匹配函数和类声明）"""
    import re
    # 匹配大多数语言中类似 function name(...) 或 class Name {...} 的结构
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

    # 安全增强：使用更严格的路径规范化
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
        # 安全检查：确保不会跟随符号链接到危险位置
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
          # 跳过无法访问的文件/目录
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

  MAX_PHYSICAL_FILE_SIZE = cvs_settings.tool_settings.read_max_physical_file_size
  MAX_RETURNED_CONTENT_CHARS = cvs_settings.tool_settings.read_max_returned_content_chars

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
      "reason": {"type": "string", "description": "备份原因（例如：修改配置文件前的自动备份）"},
    },
    "required": ["path"],
  }

  def execute(self, path: str, reason: str = "破坏性修改前的自动备份", **kwargs) -> Dict:
    # 1. 权限检查（备份需要读权限）
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    # 2. 路径安全检查
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

      # 3. 生成符合格式的备份路径
      # 获取不带后缀的路径 (base) 和 后缀 (ext)
      base, ext = os.path.splitext(real_path)

      # 格式化时间戳 (例如: 20231027_103000)
      timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

      # 拼接新路径: xxx-{timestamp}.ext
      backup_path = f"{base}-{timestamp}{ext}"

      # 4. 执行物理复制 (copy2 会尝试保留元数据)
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

  # 内容大小限制常量
  MAX_CONTENT_SIZE = cvs_settings.tool_settings.write_max_content_size  # 50MB

  def execute(self, path: str, content: str, encoding: str = "utf-8", reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "write", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

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

  # 内容大小限制常量
  MAX_APPEND_SIZE = cvs_settings.tool_settings.append_max_append_size  # 10MB

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

  # 命令限制常量
  MAX_COMMAND_LENGTH = cvs_settings.tool_settings.shell_max_command_length
  MAX_ARGS_COUNT = cvs_settings.tool_settings.shell_max_args_count
  MAX_TIMEOUT = cvs_settings.tool_settings.shell_max_timeout

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
          "return_code": result.returncode,
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
    print("\n" + "─" * 60)
    print("💬 [CVA 向您提问]")
    if context:
      print(f"   背景: {context}")
    print(f"   问题: {question}")
    print("─" * 60)
    try:
      answer = input("   您的回答: ").strip()
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

  # 搜索限制常量
  MAX_MATCHES = cvs_settings.tool_settings.search_max_matches
  MAX_FILE_SIZE = cvs_settings.tool_settings.search_max_file_size  # 10MB
  PROGRESS_INTERVAL = cvs_settings.tool_settings.progress_interval  # 每处理50个文件输出一次进度

  def execute(self, pattern: str, path: str = ".",
      search_content: bool = False, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None or not os.path.exists(real_path):
      return err("INVALID_PATH", "路径不存在")

    try:
      matches = []
      file_count = 0

      if not search_content:
        # 文件名搜索
        for found in glob_module.glob(os.path.join(real_path, "**", pattern), recursive=True):
          if self._is_safe_path(found, real_path):
            matches.append({"path": found, "type": "filename"})
            if len(matches) >= self.MAX_MATCHES:
              break
      else:
        # 内容搜索（带进度反馈）
        print(f"[搜索] 正在搜索内容: {pattern}")
        for root, dirs, files in os.walk(real_path):
          dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ('bin', 'etc', 'usr')]
          for fname in files:
            if fname.startswith("."):
              continue
            fpath = os.path.join(root, fname)
            if not self._is_safe_path(fpath, real_path):
              continue

            file_count += 1
            # 进度反馈
            if file_count % self.PROGRESS_INTERVAL == 0:
              print(f"[搜索] 已处理 {file_count} 个文件，找到 {len(matches)} 个匹配")

            try:
              if os.path.getsize(fpath) > self.MAX_FILE_SIZE:
                continue
              with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
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
  # 请求限制常量
  MAX_TIMEOUT = cvs_settings.tool_settings.max_timeout
  MAX_BODY_SIZE = cvs_settings.tool_settings.max_body_size

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
      "strategy": {"type": "string", "description": "采用的策略（例如：先搜索后修改，或编写 Python 脚本批量处理）"}
    },
    "required": ["goal", "milestones"]
  }

  def execute(self, goal: str, milestones: list, strategy: str = "", **kwargs) -> Dict:
    # 纯记录工具，返回确认信息
    return ok({
      "status": "PLAN_ACCEPTED",
      "message": "计划已备案。请开始按计划执行，并在遇到重大阻碍时更新计划。",
      "current_goal": goal
    })


class ExecutePythonScriptTool(Tool):
  name = "execute_python_script"
  description = "【高阶工具】在受控环境中执行一段 Python 代码。适合处理大批量文件、复杂逻辑计算或自定义数据分析。代码可以直接使用标准库。"
  input_schema = {
    "type": "object",
    "properties": {
      "script": {"type": "string", "description": "完整的 Python 代码字符串"},
      "reason": {"type": "string", "description": "执行该脚本的目的"}
    },
    "required": ["script"]
  }

  def execute(self, script: str, reason: str = "", **kwargs) -> Dict:
    # 强制走越权审批，因为脚本能力太强
    # 修复：target 用 "python3" 才能命中 YAML shell 白名单，"PythonRuntime" 永远匹配不上
    allowed, msg = self._check(self.name, "python3", "shell", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as tmp:
      tmp.write(script)
      tmp_path = tmp.name

    try:
      # 限制执行时间
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
  description = "【项目语义地图】利用系统级 ctags 引擎生成整个项目的符号索引（类、函数、接口、宏）。在处理大型项目、查找跨文件定义、理解代码架构时必用。比 list_directory 更省 Token 且包含语义信息。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "起始目录", "default": "."},
      "reason": {"type": "string", "description": "调用原因"}
    }
  }

  def execute(self, path: str = ".", reason: str = "", **kwargs) -> Dict:
    # 1. 权限检查 (复用你的 CVA 权限检查器)
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if not real_path or not os.path.exists(real_path):
      return err("INVALID_PATH", f"路径不存在: {path}")

    # 2. 调用系统 ctags (确保你已执行 sudo pacman -S ctags)
    # --fields=+n+S: 包含行号和函数签名
    cmd = cvs_settings.tool_settings.repo_map_cmd + [real_path]

    try:
      result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
      if result.returncode != 0:
        return err("CTAGS_ERROR", result.stderr or "未知 ctags 错误")

      # 3. 数据解析与聚合
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
        except:
          continue

      # 4. 生成“压缩大纲”格式 (AI 最容易理解的格式)
      repo_map = []
      for fpath in sorted(tags_by_file.keys()):
        rel_fpath = os.path.relpath(fpath, real_path)
        repo_map.append(f"file: {rel_fpath}")

        # 按行号排序
        tags = sorted(tags_by_file[fpath], key=lambda x: x.get("line", 0))
        for t in tags:
          kind, name, sign, line = t.get("kind"), t.get("name"), t.get("signature", ""), t.get("line", 0)
          if kind in ("variable", "local", "parameter"):
            continue  # 过滤局部变量

          indent = "  "
          if kind in ("method", "member", "field"):
            indent = "    "
          repo_map.append(f"{indent}{kind} {name}{sign} [line:{line}]")
        repo_map.append("")

      final_text = "\n".join(repo_map)

      # 5. Token 保护
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


# ─── 工具注册表 ───────────────────────────────────────────────

TOOL_REGISTRY = {
  "find_symbol": FindSymbolTool,
  "get_project_summary": GetProjectSummaryTool,
  "get_file_skeleton": GetFileSkeletonTool,
  "list_directory": ListDirectoryTool,
  "read_file": ReadFileTool,
  "backup_file": BackupFileTool,
  "write_file": WriteFileTool,
  "append_file": AppendFileTool,
  "run_shell": RunShellTool,
  "ask_human": AskHumanTool,
  "search_files": SearchFilesTool,
  "http_request": HttpRequestTool,
  "submit_plan": SubmitPlanTool,
  "execute_python_script": ExecutePythonScriptTool,
  "get_repo_map": GetRepoMapTool
}


def build_tools(capabilities: list, check_fn: Callable) -> Dict[str, Tool]:
  tools = {}
  for cap in capabilities:
    cls = TOOL_REGISTRY.get(cap)
    if cls:
      tools[cap] = cls(check_fn)
  return tools
