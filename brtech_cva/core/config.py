# core/config.py
import os
from dataclasses import dataclass, field
from typing import Set, Any


def get_env(key: str, default: Any, cast_type: type = str):
  val = os.getenv(key)
  if val is None:
    return default
  try:
    if cast_type == bool:
      return val.lower() in ("true", "1", "yes")
    if cast_type in (list, set):
      return cast_type(p.strip() for p in val.split(",") if p.strip())
    return cast_type(val)
  except (ValueError, TypeError):
    return default


@dataclass
class LLMSettings:
  log_dir: str = field(default_factory=lambda: get_env("LLM_LOG_DIR", "var/logs/llm"))
  default_model: str = field(default_factory=lambda: get_env("LLM_DEFAULT_MODEL", "deepseek/deepseek-chat"))
  max_retries: int = field(default_factory=lambda: get_env("LLM_MAX_RETRIES", 3, int))
  retry_delay: float = field(default_factory=lambda: get_env("LLM_RETRY_DELAY", 1.0, float))
  timeout: int = field(default_factory=lambda: get_env("LLM_TIMEOUT", 60, int))
  max_input_length: int = field(default_factory=lambda: get_env("LLM_MAX_INPUT_LENGTH", 250000, int))
  max_output_tokens: int = field(default_factory=lambda: get_env("LLM_MAX_OUTPUT_TOKENS", 8192, int))


@dataclass
class MemorySettings:
  data_dir: str = field(default_factory=lambda: get_env("MEMORY_DATA_DIR", "var/data/memory"))
  token_cache_ttl: float = field(default_factory=lambda: get_env("MEMORY_TOKEN_CACHE_TTL", 60.0, float))
  dehydration_cache_ttl: float = field(default_factory=lambda: get_env("MEMORY_DEHYDRATION_CACHE_TTL", 60.0, float))
  default_max_messages: int = field(default_factory=lambda: get_env("MEMORY_DEFAULT_MAX_MESSAGES", 200, int))
  default_token_budget: int = field(default_factory=lambda: get_env("MEMORY_DEFAULT_TOKEN_BUDGET", 50000, int))
  # 消息压缩阈值
  decision_summary_limit: int = field(default_factory=lambda: get_env("MEMORY_DECISION_SUMMARY_LIMIT", 400, int))
  process_fold_limit: int = field(default_factory=lambda: get_env("MEMORY_PROCESS_FOLD_LIMIT", 300, int))
  # 活跃消息窗口大小 (keep_last_n * factor)
  active_window_factor: int = field(default_factory=lambda: get_env("MEMORY_ACTIVE_WINDOW_FACTOR", 3, int))


@dataclass
class ToolSettings:
  # ReadFile
  read_max_physical_file_size: int = field(default_factory=lambda: get_env("TOOL_READ_MAX_PHYSICAL_FILE_SIZE", 100 * 1024 * 1024, int))  # 100MB
  read_max_returned_content_chars: int = field(default_factory=lambda: get_env("TOOL_READ_MAX_RETURNED_CONTENT_CHARS", 30000, int))  # 字符限制

  # Write/Append
  write_max_content_size: int = field(default_factory=lambda: get_env("TOOL_WRITE_MAX_CONTENT_SIZE", 50 * 1024 * 1024, int))  # 50MB
  append_max_append_size: int = field(default_factory=lambda: get_env("TOOL_APPEND_MAX_APPEND_SIZE", 10 * 1024 * 1024, int))  # 10MB

  # Shell
  shell_max_command_length: int = field(default_factory=lambda: get_env("TOOL_SHELL_MAX_COMMAND_LENGTH", 10000, int))
  shell_max_args_count: int = field(default_factory=lambda: get_env("TOOL_SHELL_MAX_ARGS_COUNT", 100, int))
  shell_default_timeout: int = field(default_factory=lambda: get_env("TOOL_SHELL_DEFAULT_TIMEOUT", 30, int))
  shell_max_timeout: int = field(default_factory=lambda: get_env("TOOL_SHELL_MAX_TIMEOUT", 300, int))

  # Search
  search_max_matches: int = field(default_factory=lambda: get_env("TOOL_SEARCH_MAX_MATCHES", 200, int))
  search_max_file_size: int = field(default_factory=lambda: get_env("TOOL_SEARCH_MAX_FILE_SIZE", 10 * 1024 * 1024, int))  # 10MB

  # RepoMap
  repo_map_char_limit: int = field(default_factory=lambda: get_env("TOOL_REPO_MAP_CHAR_LIMIT", 20000, int))

  # Python Runtime
  python_exec_timeout: int = field(default_factory=lambda: get_env("TOOL_PYTHON_EXEC_TIMEOUT", 60, int))

  progress_interval: int = field(default_factory=lambda: get_env("TOOL_PROGRESS_INTERVAL", 50, int))  # 每处理50个文件输出一次进度

  max_timeout: int = field(default_factory=lambda: get_env("TOOL_MAX_TIMEOUT", 60, int))  # 最大超时时间，单位秒
  max_body_size: int = field(default_factory=lambda: get_env("TOOL_MAX_BODY_SIZE", 10 * 1024, int))  # 10MB

  project_summary_skip_files: Set[str] = field(default_factory=lambda: get_env("TOOL_PROJECT_SUMMARY_SKIP_FILES", {
    '.', '__pycache__', 'node_modules', 'venv', 'logs', 'temp_backup'
  }, set))

  find_symbol_skip_start_with: Set[str] = field(default_factory=lambda: get_env("TOOL_FIND_SYMBOL_SKIP_START_WITH", {
    '.', '__pycache__', 'node_modules'
  }, set))

  find_symbol_skip_end_with: Set[str] = field(default_factory=lambda: get_env("TOOL_FIND_SYMBOL_SKIP_END_WITH", {
    '.py', '.js', '.ts', '.go', '.java', '.cpp'
  }, set))

  repo_map_cmd: list[str] = field(default_factory=lambda: get_env("TOOL_REPO_MAP_CMD", [
    "ctags", "-R", "--fields=+n+S", "--output-format=json", "--exclude=.git", "--exclude=node_modules", "--exclude=build", "--exclude=venv"
  ], list))


@dataclass
class SecuritySettings:
  # 危险路径前缀
  dangerous_path_prefixes: Set[str] = field(default_factory=lambda: get_env("SECURITY_DANGEROUS_PATH_PREFIXES", {
    '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin',
    '/boot', '/sys', '/proc', '/dev', '/root', '~/.ssh', '~/.aws'
  }, set))

  # 危险命令黑名单
  dangerous_commands: Set[str] = field(default_factory=lambda: get_env("SECURITY_DANGEROUS_COMMANDS", {
    'rm -rf /', 'rm -rf /*', 'dd if=/dev/zero', 'mkfs',
    'chmod 777 /', 'chown root', 'sudo su', 'su root',
    ':(){ :|:& };:', 'reboot', 'shutdown', 'iptables -F'
  }, set))


@dataclass
class AuditSettings:
  log_dir: str = field(default_factory=lambda: get_env("AUDIT_LOG_DIR", "var/logs/audit", str))
  max_log_size: int = field(default_factory=lambda: get_env("AUDIT_MAX_LOG_SIZE", 100 * 1024 * 1024, int))  # 100MB
  max_log_age_days: int = field(default_factory=lambda: get_env("AUDIT_MAX_LOG_AGE_DAYS", 30, int))
  cleanup_interval_seconds: int = field(default_factory=lambda: get_env("AUDIT_CLEANUP_INTERVAL_SECONDS", 300, int))  # 5分钟清理一次过期权限


@dataclass
class CvaSettings:
  agent_dir: str = field(default_factory=lambda: get_env("AGENT_DIR", "var/agent"))
  llm_settings: LLMSettings = field(default_factory=LLMSettings)
  memory_settings: MemorySettings = field(default_factory=MemorySettings)
  tool_settings: ToolSettings = field(default_factory=ToolSettings)
  security_settings: SecuritySettings = field(default_factory=SecuritySettings)
  audit_settings: AuditSettings = field(default_factory=AuditSettings)


# 全局单例
cva_settings = CvaSettings()
