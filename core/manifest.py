"""
属性配置包（Role Manifest）— 加载、校验、数据模型
"""

import os
from dataclasses import dataclass, field
from typing import List

import yaml


@dataclass
class EscalationPolicy:
  auto_deny_patterns: List[str] = field(default_factory=list)
  notify_channel: str = "console"  # console | slack | webhook
  timeout_seconds: int = 300  # 超时后自动拒绝


@dataclass
class Permissions:
  list: List[str] = field(default_factory=list)
  read: List[str] = field(default_factory=list)
  write: List[str] = field(default_factory=list)
  shell: List[str] = field(default_factory=list)


@dataclass
class RoleManifest:
  role_name: str
  version: str
  identity_prompt: str
  init_permissions: Permissions
  capabilities: List[str]
  escalation_policy: EscalationPolicy
  max_tokens: int = 8192

  # 全量合法 capability 集合
  VALID_CAPABILITIES = {
    "find_symbol",
    "get_project_summary",
    "get_file_skeleton",
    "list_directory",
    "read_file",
    "backup_file",
    "write_file",
    "append_file",
    "run_shell",
    "ask_human",
    "search_files",
    "http_request",
    "submit_plan",
    "execute_python_script",
    "get_repo_map"
  }

  def validate(self):
    """校验 Manifest 配置合法性"""
    errors = []

    if not self.role_name:
      errors.append("role_name 不能为空")
    if not self.identity_prompt:
      errors.append("identity_prompt 不能为空")

    invalid_caps = set(self.capabilities) - self.VALID_CAPABILITIES
    if invalid_caps:
      errors.append(f"无效的 capabilities: {invalid_caps}")

    if self.escalation_policy.notify_channel not in ("console", "slack", "webhook"):
      errors.append("notify_channel 必须为 console / slack / webhook 之一")

    if errors:
      raise ValueError(f"Manifest 校验失败:\n  " + "\n  ".join(errors))


def load_manifest(path: str) -> RoleManifest:
  """从 YAML 文件加载并解析 Role Manifest"""
  if not os.path.exists(path):
    raise FileNotFoundError(f"Manifest 文件不存在: {path}")

  with open(path, "r", encoding="utf-8") as f:
    raw = yaml.safe_load(f)

  # 解析 permissions
  perm_raw = raw.get("init_permissions", {})
  permissions = Permissions(
      list=perm_raw.get("list", []),  # ← 修复：补全缺失的 list 字段
      read=perm_raw.get("read", []),
      write=perm_raw.get("write", []),
      shell=perm_raw.get("shell", []),
  )

  # 解析 escalation_policy
  esc_raw = raw.get("escalation_policy", {})
  escalation = EscalationPolicy(
      auto_deny_patterns=esc_raw.get("auto_deny_patterns", []),
      notify_channel=esc_raw.get("notify_channel", "console"),
      timeout_seconds=esc_raw.get("timeout_seconds", 300),
  )

  manifest = RoleManifest(
      role_name=raw["role_name"],
      version=str(raw.get("version", "1.0")),
      identity_prompt=raw["identity_prompt"],
      init_permissions=permissions,
      capabilities=raw.get("capabilities", []),
      escalation_policy=escalation,
      max_tokens=raw.get("max_tokens", 8192),
  )

  manifest.validate()
  return manifest
