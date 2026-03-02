"""
原子工具集（Tool Catalog）
每个工具：输入参数校验 → 权限检查 → 执行 → 返回结构化结果
"""

import glob as glob_module
import os
import subprocess
from typing import Any, Callable, Dict, Optional


# ─── 工具返回值规范 ──────────────────────────────────────────

def ok(data: Any) -> Dict:
  return {"status": "ok", "data": data}


def err(code: str, message: str) -> Dict:
  return {"status": "error", "error_code": code, "message": message}


# ─── 工具基类 ────────────────────────────────────────────────

class BaseTool:
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

  def to_api_spec(self) -> Dict:
    return {
      "name": self.name,
      "description": self.description,
      "input_schema": self.input_schema,
    }


# ─── 具体工具实现 ─────────────────────────────────────────────

class ListDirectoryTool(BaseTool):
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

  def execute(self, path: str, reason: str = "", **_) -> Dict:
    allowed, msg = self._check(self.name, path, "list", reason)
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))
    if not os.path.exists(real_path):
      return err("NOT_FOUND", f"路径不存在: {path}")
    if not os.path.isdir(real_path):
      return err("NOT_A_DIRECTORY", f"不是目录: {path}")

    try:
      entries = []
      for name in sorted(os.listdir(real_path)):
        full = os.path.join(real_path, name)
        stat = os.stat(full)
        entries.append({
          "name": name,
          "type": "dir" if os.path.isdir(full) else "file",
          "size": stat.st_size,
          "path": full,
        })
      return ok({"path": real_path, "entries": entries, "count": len(entries)})
    except PermissionError as e:
      return err("OS_PERMISSION_DENIED", str(e))


class ReadFileTool(BaseTool):
  name = "read_file"
  description = "读取文件内容并返回。支持文本文件，超大文件自动截断。"
  input_schema = {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "文件路径"},
      "encoding": {"type": "string", "description": "字符编码（默认 utf-8）"},
      "max_chars": {"type": "integer", "description": "最大返回字符数（默认 50000）"},
      "reason": {"type": "string"},
    },
    "required": ["path"],
  }

  def execute(self, path: str, encoding: str = "utf-8",
      max_chars: int = 50000, reason: str = "", **_) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason)
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))
    if not os.path.exists(real_path):
      return err("NOT_FOUND", f"文件不存在: {path}")
    if os.path.isdir(real_path):
      return err("IS_A_DIRECTORY", f"路径是目录，请使用 list_directory: {path}")

    try:
      size = os.path.getsize(real_path)
      with open(real_path, "r", encoding=encoding, errors="replace") as f:
        content = f.read(max_chars)
      truncated = size > max_chars * 4  # 粗略估算
      return ok({
        "path": real_path,
        "content": content,
        "size_bytes": size,
        "truncated": truncated,
        "encoding": encoding,
      })
    except UnicodeDecodeError:
      return err("DECODE_ERROR", f"文件编码错误，尝试指定 encoding 参数")
    except OSError as e:
      return err("IO_ERROR", str(e))


class WriteFileTool(BaseTool):
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

  def execute(self, path: str, content: str,
      encoding: str = "utf-8", reason: str = "", **_) -> Dict:
    allowed, msg = self._check(self.name, path, "write", reason)
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))
    try:
      os.makedirs(os.path.dirname(real_path) or ".", exist_ok=True)
      with open(real_path, "w", encoding=encoding) as f:
        f.write(content)
      return ok({"path": real_path, "bytes_written": len(content.encode(encoding))})
    except OSError as e:
      return err("IO_ERROR", str(e))


class AppendFileTool(BaseTool):
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

  def execute(self, path: str, content: str, reason: str = "", **_) -> Dict:
    allowed, msg = self._check(self.name, path, "write", reason)
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))
    try:
      os.makedirs(os.path.dirname(real_path) or ".", exist_ok=True)
      with open(real_path, "a", encoding="utf-8") as f:
        f.write(content)
      return ok({"path": real_path, "bytes_appended": len(content.encode())})
    except OSError as e:
      return err("IO_ERROR", str(e))


class RunShellTool(BaseTool):
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

  def execute(self, command: str, timeout: int = 30,
      cwd: Optional[str] = None, reason: str = "", **_) -> Dict:
    allowed, msg = self._check(self.name, command, "shell", reason)
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    timeout = min(timeout, 300)  # 硬限制 300s
    try:
      result = subprocess.run(
          command,
          shell=False,  # 安全：不使用 shell=True
          args=command.split(),  # 简单分割（复杂命令可用 shlex.split）
          capture_output=True,
          text=True,
          timeout=timeout,
          cwd=cwd,
      )
      return ok({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
        "command": command,
      })
    except subprocess.TimeoutExpired:
      return err("TIMEOUT", f"命令超时（{timeout}s）: {command}")
    except FileNotFoundError:
      return err("COMMAND_NOT_FOUND", f"命令不存在: {command.split()[0]}")
    except Exception as e:
      return err("EXEC_ERROR", str(e))


class AskHumanTool(BaseTool):
  name = "ask_human"
  description = "向人类导师提问，挂起当前任务等待文字回复。用于需要人类判断的关键决策点。"
  input_schema = {
    "type": "object",
    "properties": {
      "question": {"type": "string", "description": "向人类提出的问题"},
      "context": {"type": "string", "description": "问题背景（帮助人类理解）"},
    },
    "required": ["question"],
  }

  def execute(self, question: str, context: str = "", **_) -> Dict:
    # ask_human 不需要权限检查
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
      return err("NO_INPUT", "未获得人类输入（非交互模式）")


class SearchFilesTool(BaseTool):
  name = "search_files"
  description = "在指定目录内搜索匹配模式的文件名或文件内容。"
  input_schema = {
    "type": "object",
    "properties": {
      "pattern": {"type": "string", "description": "搜索模式（文件名 glob 或内容关键词）"},
      "path": {"type": "string", "description": "搜索根目录（默认当前目录）"},
      "search_content": {"type": "boolean", "description": "是否搜索文件内容（默认 False，只搜文件名）"},
      "reason": {"type": "string"},
    },
    "required": ["pattern"],
  }

  def execute(self, pattern: str, path: str = ".",
      search_content: bool = False, reason: str = "", **_) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason)
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    real_path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))
    if not os.path.exists(real_path):
      return err("NOT_FOUND", f"目录不存在: {path}")

    try:
      matches = []
      if not search_content:
        # 文件名搜索
        for found in glob_module.glob(
            os.path.join(real_path, "**", pattern), recursive=True
        ):
          matches.append({"path": found, "type": "filename"})
      else:
        # 内容搜索
        for root, dirs, files in os.walk(real_path):
          # 跳过隐藏目录
          dirs[:] = [d for d in dirs if not d.startswith(".")]
          for fname in files:
            fpath = os.path.join(root, fname)
            try:
              with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                  if pattern.lower() in line.lower():
                    matches.append({
                      "path": fpath,
                      "line": i,
                      "content": line.rstrip(),
                      "type": "content",
                    })
                    if len(matches) >= 200:  # 结果上限
                      break
            except OSError:
              continue
          if len(matches) >= 200:
            break

      return ok({"matches": matches[:200], "count": len(matches), "pattern": pattern})
    except Exception as e:
      return err("SEARCH_ERROR", str(e))


class HttpRequestTool(BaseTool):
  name = "http_request"
  description = "发起 HTTP 请求。目标域名须在权限白名单中注册（shell 权限条目以 http:// 或 https:// 开头）。"
  input_schema = {
    "type": "object",
    "properties": {
      "url": {"type": "string", "description": "目标 URL"},
      "method": {"type": "string", "description": "HTTP 方法（GET/POST/PUT/DELETE）"},
      "headers": {"type": "object", "description": "请求头"},
      "body": {"type": "string", "description": "请求体（JSON 字符串）"},
      "timeout": {"type": "integer", "description": "超时秒数（默认 15）"},
      "reason": {"type": "string"},
    },
    "required": ["url", "method"],
  }

  def execute(self, url: str, method: str = "GET", headers: dict = None,
      body: str = None, timeout: int = 15, reason: str = "", **_) -> Dict:
    # 用 shell 权限类型检查 URL（以域名/URL 前缀作为权限条目）
    allowed, msg = self._check(self.name, url, "shell", reason)
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    try:
      import urllib.request
      import urllib.error
      import json as _json

      req = urllib.request.Request(
          url,
          method=method.upper(),
          headers=headers or {},
          data=body.encode() if body else None,
      )
      with urllib.request.urlopen(req, timeout=min(timeout, 60)) as resp:
        resp_body = resp.read().decode("utf-8", errors="replace")
        return ok({
          "status_code": resp.status,
          "headers": dict(resp.headers),
          "body": resp_body[:10000],  # 截断超大响应
          "truncated": len(resp_body) > 10000,
        })
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


def build_tools(capabilities: list, check_fn: Callable) -> Dict[str, BaseTool]:
  """根据 Manifest capabilities 构建工具实例字典"""
  tools = {}
  for cap in capabilities:
    cls = TOOL_REGISTRY.get(cap)
    if cls:
      tools[cap] = cls(check_fn)
  return tools
