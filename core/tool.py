"""
原子工具集（Tool Catalog）v3.2 - Token优化版
优化内容：
- 搜索工具添加进度反馈
- 改进错误处理，使用更具体的异常类型
- 优化文件大小检查逻辑
- 降低默认文件读取限制：50000 -> 30000字符，节省token
"""

import glob as glob_module
import os
import shlex
import subprocess
import time
from typing import Any, Callable, Dict, Optional


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

  def execute(self, **kwargs) -> Dict:
    raise NotImplementedError

  def _ctx(self, kwargs: dict) -> str:
    """从 execute kwargs 中提取对话上下文摘要（由 shell._dispatch_tool 注入）"""
    return kwargs.get("_context_summary", "")

  def to_api_spec(self) -> Dict:
    return {
      "name": self.name,
      "description": self.description,
      "input_schema": self.input_schema,
    }


# ─── 具体工具实现 ─────────────────────────────────────────────

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

  def _secure_path(self, path: str) -> Optional[str]:
    """安全的路径规范化，防止路径穿越和符号链接攻击"""
    try:
      # 展开用户目录并规范化
      expanded = os.path.expanduser(path)
      # 获取绝对路径
      abs_path = os.path.abspath(expanded)
      # 规范化路径（解析 .. 和 .）
      norm_path = os.path.normpath(abs_path)

      # 检查路径是否包含危险字符
      if any(char in norm_path for char in ['\x00', '\n', '\r']):
        return None

      return norm_path
    except (ValueError, OSError):
      return None


class ReadFileTool(Tool):
  name = "read_file"
  description = "读取文件内容。返回结构化的 JSON，包含元数据和全文。请注意，为了节省 Token，旧的文件记忆可能会被底座自动脱水压缩。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "完整路径"},
      "reason": {"type": "string", "description": "【关键】如果路径可能越权，请提供申请理由"},
      "encoding": {"type": "string", "description": "文件编码（默认 utf-8）"},
      "max_chars": {"type": "integer", "description": "最大读取字符数（默认 50000）"},
    },
    "required": ["path", "reason"],  # 强制要求理由
  }

  # 文件大小限制常量
  MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

  def execute(self, path: str, encoding: str = "utf-8",
      max_chars: int = 30000, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

    if not os.path.exists(real_path):
      return err("NOT_FOUND", f"文件不存在: {path}")
    if os.path.isdir(real_path):
      return err("IS_A_DIRECTORY", f"路径是目录，请使用 list_directory: {path}")

    try:
      size = os.path.getsize(real_path)
      # 安全检查：限制读取的文件大小
      if size > self.MAX_FILE_SIZE:
        return err("FILE_TOO_LARGE", f"文件过大（{size} bytes），超过限制（{self.MAX_FILE_SIZE} bytes）")

      with open(real_path, "r", encoding=encoding, errors="replace") as f:
        content = f.read(max_chars)

      # ─── 结构化 Artifact 返回 ───
      artifact = {
        "artifact_type": "file_content",
        "metadata": {
          "path": real_path,
          "size": size,
          "encoding": encoding,
          "is_full_text": True,
          "read_at": time.time()
        },
        "content": content
      }
      return ok(artifact)

    except UnicodeDecodeError:
      return err("DECODE_ERROR", f"文件编码错误，尝试指定 encoding 参数")
    except OSError as e:
      return err("IO_ERROR", str(e))

  def _secure_path(self, path: str) -> Optional[str]:
    """安全的路径规范化"""
    try:
      expanded = os.path.expanduser(path)
      abs_path = os.path.abspath(expanded)
      norm_path = os.path.normpath(abs_path)
      if any(char in norm_path for char in ['\x00', '\n', '\r']):
        return None
      return norm_path
    except (ValueError, OSError):
      return None


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
  MAX_CONTENT_SIZE = 50 * 1024 * 1024  # 50MB

  def execute(self, path: str, content: str,
      encoding: str = "utf-8", reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "write", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

    content_bytes = content.encode(encoding)
    if len(content_bytes) > self.MAX_CONTENT_SIZE:
      return err("CONTENT_TOO_LARGE", f"内容过大超过 {self.MAX_CONTENT_SIZE // (1024*1024)}MB 限制")

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

  def _secure_path(self, path: str) -> Optional[str]:
    try:
      expanded = os.path.expanduser(path)
      abs_path = os.path.abspath(expanded)
      norm_path = os.path.normpath(abs_path)
      if any(char in norm_path for char in ['\x00', '\n', '\r']):
        return None
      return norm_path
    except (ValueError, OSError):
      return None


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
  MAX_APPEND_SIZE = 10 * 1024 * 1024  # 10MB

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

  def _secure_path(self, path: str) -> Optional[str]:
    try:
      expanded = os.path.expanduser(path)
      abs_path = os.path.abspath(expanded)
      norm_path = os.path.normpath(abs_path)
      if any(char in norm_path for char in ['\x00', '\n', '\r']):
        return None
      return norm_path
    except (ValueError, OSError):
      return None


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
  MAX_COMMAND_LENGTH = 10000
  MAX_ARGS_COUNT = 100
  MAX_TIMEOUT = 300

  def execute(self, command: str, timeout: int = 30,
      cwd: Optional[str] = None, reason: str = "", **kwargs) -> Dict:
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

  def _secure_path(self, path: str) -> Optional[str]:
    try:
      expanded = os.path.expanduser(path)
      abs_path = os.path.abspath(expanded)
      norm_path = os.path.normpath(abs_path)
      if any(char in norm_path for char in ['\x00', '\n', '\r']):
        return None
      return norm_path
    except (ValueError, OSError):
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
  MAX_MATCHES = 200
  MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
  PROGRESS_INTERVAL = 50  # 每处理50个文件输出一次进度

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

  def _secure_path(self, path: str) -> Optional[str]:
    try:
      expanded = os.path.expanduser(path)
      abs_path = os.path.abspath(expanded)
      norm_path = os.path.normpath(abs_path)
      return norm_path
    except Exception:
      return None

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
  MAX_TIMEOUT = 60
  MAX_BODY_SIZE = 10000

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


# ─── 工具注册表 ───────────────────────────────────────────────

TOOL_REGISTRY = {
  "list_directory": ListDirectoryTool,
  "read_file": ReadFileTool,
  "write_file": WriteFileTool,
  "append_file": AppendFileTool,
  "run_shell": RunShellTool,
  "ask_human": AskHumanTool,
  "search_files": SearchFilesTool,
  "http_request": HttpRequestTool,
}


def build_tools(capabilities: list, check_fn: Callable) -> Dict[str, Tool]:
  tools = {}
  for cap in capabilities:
    cls = TOOL_REGISTRY.get(cap)
    if cls:
      tools[cap] = cls(check_fn)
  return tools
