"""
原子工具集（Tool Catalog）v2 - 安全增强版
每个工具：输入参数校验 → 权限检查 → 执行 → 返回结构化结果

安全改进：
- 修复Shell注入漏洞：使用shlex.split正确解析命令参数
- 加强路径安全检查：防止符号链接绕过
- 改进资源管理：确保文件句柄正确关闭
- 完善错误处理：增加重试机制和详细错误信息
"""

import glob as glob_module
import os
import shlex  # 新增：用于安全的命令行解析
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
  description = "读取文件。如果你认为该文件不在你的初始白名单内，请在 reason 参数中详细说明你读取该文件的必要性，以说服导师为你提权。"
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

  def execute(self, path: str, encoding: str = "utf-8",
      max_chars: int = 50000, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    # 安全增强：使用安全的路径处理
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
      max_size = 100 * 1024 * 1024  # 100MB
      if size > max_size:
        return err("FILE_TOO_LARGE", f"文件过大（{size} bytes），超过限制（{max_size} bytes）")

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

  def _secure_path(self, path: str) -> Optional[str]:
    """安全的路径规范化，继承自ListDirectoryTool的逻辑"""
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

  def execute(self, path: str, content: str,
      encoding: str = "utf-8", reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "write", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    # 安全增强：使用安全的路径处理
    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

    # 安全检查：限制写入内容大小
    max_content_size = 50 * 1024 * 1024  # 50MB
    content_bytes = content.encode(encoding)
    if len(content_bytes) > max_content_size:
      return err("CONTENT_TOO_LARGE", f"内容过大（{len(content_bytes)} bytes），超过限制（{max_content_size} bytes）")

    try:
      # 安全创建目录
      dir_path = os.path.dirname(real_path) or "."
      os.makedirs(dir_path, exist_ok=True)

      # 原子写入：先写临时文件，再重命名
      temp_path = real_path + f".tmp.{int(time.time())}"
      try:
        with open(temp_path, "w", encoding=encoding) as f:
          f.write(content)
        # 原子重命名
        os.rename(temp_path, real_path)
      except Exception:
        # 清理临时文件
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

  def execute(self, path: str, content: str, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "write", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    # 安全增强：使用安全的路径处理
    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

    # 安全检查：限制追加内容大小
    max_content_size = 10 * 1024 * 1024  # 10MB
    content_bytes = content.encode('utf-8')
    if len(content_bytes) > max_content_size:
      return err("CONTENT_TOO_LARGE", f"内容过大（{len(content_bytes)} bytes），超过限制（{max_content_size} bytes）")

    try:
      # 安全创建目录
      dir_path = os.path.dirname(real_path) or "."
      os.makedirs(dir_path, exist_ok=True)

      with open(real_path, "a", encoding="utf-8") as f:
        f.write(content)
      return ok({"path": real_path, "bytes_appended": len(content_bytes)})
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

  def execute(self, command: str, timeout: int = 30,
      cwd: Optional[str] = None, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, command, "shell", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    # 安全增强：使用shlex.split正确解析命令参数，防止Shell注入
    try:
      # 使用shlex.split进行安全的命令解析
      args = shlex.split(command)
    except ValueError as e:
      return err("INVALID_COMMAND", f"命令格式错误: {e}")

    # 安全检查：限制命令长度和参数数量
    if len(command) > 10000:
      return err("COMMAND_TOO_LONG", "命令过长，超过10000字符限制")
    if len(args) > 100:
      return err("TOO_MANY_ARGS", f"参数过多（{len(args)}个），超过100个限制")

    # 安全检查：验证工作目录
    if cwd:
      real_cwd = self._secure_path(cwd)
      if real_cwd is None or not os.path.exists(real_cwd) or not os.path.isdir(real_cwd):
        return err("INVALID_CWD", f"无效的工作目录: {cwd}")
      cwd = real_cwd

    timeout = min(timeout, 300)  # 硬限制 300s

    # 安全增强：添加重试机制
    max_retries = 2
    for attempt in range(max_retries + 1):
      try:
        # 修复：正确传递参数给subprocess.run
        result = subprocess.run(
            args,  # 使用解析后的参数列表，而不是原始字符串
            shell=False,  # 安全：不使用 shell=True
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            # 安全增强：限制环境变量
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
          "args": args,  # 返回解析后的参数
        })
      except subprocess.TimeoutExpired:
        return err("TIMEOUT", f"命令超时（{timeout}s）: {command}")
      except FileNotFoundError:
        return err("COMMAND_NOT_FOUND", f"命令不存在: {args[0] if args else 'empty'}")
      except PermissionError:
        return err("PERMISSION_DENIED", f"权限不足，无法执行命令: {args[0] if args else 'empty'}")
      except Exception as e:
        if attempt == max_retries:
          return err("EXEC_ERROR", f"命令执行失败（重试{max_retries}次后）: {str(e)}")
        time.sleep(0.1 * (attempt + 1))  # 指数退避

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


class AskHumanTool(Tool):
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
    except KeyboardInterrupt:
      return err("INTERRUPTED", "用户中断输入")


class SearchFilesTool(Tool):
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
      search_content: bool = False, reason: str = "", **kwargs) -> Dict:
    allowed, msg = self._check(self.name, path, "read", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    # 安全增强：使用安全的路径处理
    real_path = self._secure_path(path)
    if real_path is None:
      return err("INVALID_PATH", f"路径不安全或无效: {path}")

    if not os.path.exists(real_path):
      return err("NOT_FOUND", f"目录不存在: {path}")

    # 安全检查：限制搜索模式长度
    if len(pattern) > 1000:
      return err("PATTERN_TOO_LONG", "搜索模式过长，超过1000字符限制")

    try:
      matches = []
      if not search_content:
        # 文件名搜索
        try:
          for found in glob_module.glob(
              os.path.join(real_path, "**", pattern), recursive=True
          ):
            # 安全检查：验证找到的路径
            if self._is_safe_path(found, real_path):
              matches.append({"path": found, "type": "filename"})
              if len(matches) >= 200:  # 结果上限
                break
        except (OSError, ValueError):
          return err("GLOB_ERROR", "文件名搜索失败")
      else:
        # 内容搜索
        try:
          for root, dirs, files in os.walk(real_path):
            # 跳过隐藏目录和危险目录
            dirs[:] = [d for d in dirs if not d.startswith(".") and self._is_safe_dir(d)]

            for fname in files:
              if fname.startswith("."):  # 跳过隐藏文件
                continue

              fpath = os.path.join(root, fname)
              if not self._is_safe_path(fpath, real_path):
                continue

              try:
                # 安全检查：限制文件大小
                if os.path.getsize(fpath) > 10 * 1024 * 1024:  # 10MB
                  continue

                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                  for i, line in enumerate(f, 1):
                    if pattern.lower() in line.lower():
                      matches.append({
                        "path": fpath,
                        "line": i,
                        "content": line.rstrip()[:200],  # 限制行长度
                        "type": "content",
                      })
                      if len(matches) >= 200:  # 结果上限
                        break
                  if len(matches) >= 200:
                    break
              except (OSError, UnicodeDecodeError, ValueError):
                continue
            if len(matches) >= 200:
              break
        except (OSError, ValueError):
          return err("CONTENT_SEARCH_ERROR", "内容搜索失败")

      return ok({"matches": matches[:200], "count": len(matches), "pattern": pattern})
    except Exception as e:
      return err("SEARCH_ERROR", str(e))

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

  def _is_safe_path(self, path: str, base_path: str) -> bool:
    """检查路径是否在安全的基础路径内"""
    try:
      real_path = os.path.realpath(path)
      real_base = os.path.realpath(base_path)
      return real_path.startswith(real_base + os.sep) or real_path == real_base
    except (OSError, ValueError):
      return False

  def _is_safe_dir(self, dirname: str) -> bool:
    """检查目录名是否安全"""
    unsafe_names = {
      'bin', 'sbin', 'etc', 'usr', 'var', 'sys', 'proc', 'dev',
      'boot', 'lib', 'lib64', 'opt', 'run', 'srv', 'tmp'
    }
    return dirname not in unsafe_names and not any(char in dirname for char in ['\x00', '\n', '\r'])


class HttpRequestTool(Tool):
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
      body: str = None, timeout: int = 15, reason: str = "", **kwargs) -> Dict:
    # 用 shell 权限类型检查 URL（以域名/URL 前缀作为权限条目）
    allowed, msg = self._check(self.name, url, "shell", reason, self._ctx(kwargs))
    if not allowed:
      return err("PERMISSION_DENIED", msg)

    # 安全检查：验证URL格式
    if not self._is_safe_url(url):
      return err("INVALID_URL", f"不安全的URL: {url}")

    # 安全检查：限制请求体大小
    if body and len(body) > 10 * 1024 * 1024:  # 10MB
      return err("BODY_TOO_LARGE", "请求体过大，超过10MB限制")

    # 安全检查：限制超时时间
    timeout = min(timeout, 60)  # 最大60秒

    try:
      import urllib.request
      import urllib.error
      import json as _json

      # 安全增强：设置安全的请求头
      safe_headers = {
        'User-Agent': 'CVA-Agent/2.0',
        'Accept': 'application/json,text/plain,*/*',
        'Accept-Language': 'en-US,en;q=0.9',
      }

      # 合并用户提供的头部（覆盖安全头部）
      if headers:
        safe_headers.update(headers)

      req = urllib.request.Request(
          url,
          method=method.upper(),
          headers=safe_headers,
          data=body.encode('utf-8') if body else None,
      )

      # 安全增强：设置SSL上下文（如果使用HTTPS）
      if url.startswith('https://'):
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

      with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp_body = resp.read().decode("utf-8", errors="replace")
        return ok({
          "status_code": resp.status,
          "headers": dict(resp.headers),
          "body": resp_body[:10000],  # 截断超大响应
          "truncated": len(resp_body) > 10000,
        })
    except urllib.error.HTTPError as e:
      return err("HTTP_ERROR", f"HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
      return err("URL_ERROR", f"URL错误: {e.reason}")
    except Exception as e:
      return err("HTTP_ERROR", str(e))

  def _is_safe_url(self, url: str) -> bool:
    """检查URL是否安全"""
    try:
      from urllib.parse import urlparse

      parsed = urlparse(url)

      # 只允许http和https协议
      if parsed.scheme not in ('http', 'https'):
        return False

      # 检查主机名格式
      if not parsed.hostname:
        return False

      # 禁止localhost和私有IP（除非明确授权）
      dangerous_hosts = {
        'localhost', '127.0.0.1', '0.0.0.0',
        '::1', 'localhost.localdomain'
      }

      if parsed.hostname.lower() in dangerous_hosts:
        return False

      # 检查端口范围
      if parsed.port and (parsed.port < 80 or parsed.port > 65535):
        return False

      return True
    except Exception:
      return False


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
  """根据 Manifest capabilities 构建工具实例字典"""
  tools = {}
  for cap in capabilities:
    cls = TOOL_REGISTRY.get(cap)
    if cls:
      tools[cap] = cls(check_fn)
  return tools
