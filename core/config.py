# core/config.py
from dataclasses import dataclass, field
from typing import Set


@dataclass
class LLMSettings:
  default_model: str = "claude-opus-4-5"
  max_retries: int = 3
  retry_delay: float = 1.0
  timeout: int = 60
  max_input_length: int = 250000
  max_output_tokens: int = 8192


@dataclass
class MemorySettings:
  token_cache_ttl: float = 60.0
  dehydration_cache_ttl: float = 60.0
  default_max_messages: int = 200
  default_token_budget: int = 50000
  # 消息压缩阈值
  decision_summary_limit: int = 400
  process_fold_limit: int = 300
  # 活跃消息窗口大小 (keep_last_n * factor)
  active_window_factor: int = 3


@dataclass
class ToolSettings:
  # ReadFile
  read_max_physical_file_size: int = 100 * 1024 * 1024  # 100MB
  read_max_returned_content_chars: int = 30000  # 字符限制

  # Write/Append
  write_max_content_size: int = 50 * 1024 * 1024  # 50MB
  append_max_append_size: int = 10 * 1024 * 1024  # 10MB

  # Shell
  shell_max_command_length: int = 10000
  shell_max_args_count: int = 100
  shell_default_timeout: int = 30
  shell_max_timeout: int = 300

  # Search
  search_max_matches: int = 200
  search_max_file_size: int = 10 * 1024 * 1024  # 10MB

  # RepoMap
  repo_map_char_limit: int = 20000

  # Python Runtime
  python_exec_timeout: int = 60

  progress_interval: int = 50  # 每处理50个文件输出一次进度

  max_timeout: int = 60  # 最大超时时间，单位秒
  max_body_size: int = 10 * 1024  # 10MB

  project_summary_skip_files: Set[str] = field(default_factory=lambda: {
    '.', '__pycache__', 'node_modules', 'venv', 'logs', 'temp_backup'
  })

  find_symbol_skip_start_with: Set[str] = field(default_factory=lambda: {
    '.', '__pycache__', 'node_modules'
  })

  find_symbol_skip_end_with: Set[str] = field(default_factory=lambda: {
    '.py', '.js', '.ts', '.go', '.java', '.cpp'
  })

  repo_map_cmd: list[str] = field(default_factory=lambda: {"ctags", "-R", "--fields=+n+S", "--output-format=json", "--exclude=.git", "--exclude=node_modules", "--exclude=build", "--exclude=venv"})


@dataclass
class SecuritySettings:
  # 危险路径前缀
  dangerous_path_prefixes: Set[str] = field(default_factory=lambda: {
    '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin',
    '/boot', '/sys', '/proc', '/dev', '/root', '~/.ssh', '~/.aws'
  })

  # 危险命令黑名单
  dangerous_commands: Set[str] = field(default_factory=lambda: {
    'rm -rf /', 'rm -rf /*', 'dd if=/dev/zero', 'mkfs',
    'chmod 777 /', 'chown root', 'sudo su', 'su root',
    ':(){ :|:& };:', 'reboot', 'shutdown', 'iptables -F'
  })


@dataclass
class AuditSettings:
  max_log_size: int = 100 * 1024 * 1024  # 100MB
  max_log_age_days: int = 30
  cleanup_interval_seconds: int = 300  # 5分钟清理一次过期权限


@dataclass
class CvaSettings:
  llm_settings: LLMSettings = field(default_factory=LLMSettings)
  memory_settings: MemorySettings = field(default_factory=MemorySettings)
  tool_settings: ToolSettings = field(default_factory=ToolSettings)
  security_settings: SecuritySettings = field(default_factory=SecuritySettings)
  audit_settings: AuditSettings = field(default_factory=AuditSettings)


# 全局单例
cvs_settings = CvaSettings()
