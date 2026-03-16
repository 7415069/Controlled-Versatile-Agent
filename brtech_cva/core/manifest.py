"""
属性配置包（Role Manifest）— 加载、校验、数据模型
"""

import os
from dataclasses import dataclass, field
from typing import List, Set

import yaml


@dataclass
class EscalationPolicy:
  auto_deny_patterns: List[str] = field(default_factory=list)
  notify_channel: str = "console"  # console | slack | webhook
  timeout_seconds: int = 300  # 超时后自动拒绝
  low_risk_prefixes: List[str] = field(default_factory=list)


@dataclass
class Permissions:
  list: List[str] = field(default_factory=lambda: [])
  read: List[str] = field(default_factory=lambda: [])
  write: List[str] = field(default_factory=lambda: [])
  shell: List[str] = field(default_factory=lambda: [])
  gui_control: List[str] = field(default_factory=lambda: [])


@dataclass
class RoleManifest:
  role_name: str
  version: str
  identity_prompt: str
  init_permissions: Permissions
  capabilities: List[str]
  escalation_policy: EscalationPolicy
  max_tokens: int = 8192

  def _get_all_valid_capabilities(self) -> Set[str]:
    """
    动态获取当前系统支持的所有能力：
    1. 内置工具 (tool.py 中的类)
    2. 自定义工具 (var/agent/custom_tools/ 下的文件)
    """
    # 延迟导入，避免循环依赖
    from brtech_cva.core.tool import ToolLoader

    # 获取内置工具名
    builtin_caps = set(ToolLoader._get_builtin_tool_classes().keys())

    # 获取自定义工具名
    custom_dir = ToolLoader.get_custom_tools_dir()
    custom_caps = set()
    if os.path.exists(custom_dir):
      for f in os.listdir(custom_dir):
        if f.endswith(".py") and not f.startswith("__"):
          custom_caps.add(f[:-3])

    return builtin_caps | custom_caps

  def validate(self):
    """校验 Manifest 配置合法性"""
    errors = []

    if not self.role_name:
      errors.append("role_name 不能为空")
    if not self.identity_prompt:
      errors.append("identity_prompt 不能为空")

    # 核心改动：使用动态获取的集合进行校验
    valid_set = self._get_all_valid_capabilities()
    invalid_caps = set(self.capabilities) - valid_set

    if invalid_caps:
      errors.append(f"无效或未定义的 capabilities: {invalid_caps}。请检查拼写或确认工具已合成。")

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
      list=perm_raw.get("list", []),
      read=perm_raw.get("read", []),
      write=perm_raw.get("write", []),
      shell=perm_raw.get("shell", []),
      gui_control=perm_raw.get("gui_control", []),
  )

  # 解析 escalation_policy
  esc_raw = raw.get("escalation_policy", {})
  escalation = EscalationPolicy(
      auto_deny_patterns=esc_raw.get("auto_deny_patterns", []),
      notify_channel=esc_raw.get("notify_channel", "console"),
      timeout_seconds=esc_raw.get("timeout_seconds", 300),
      low_risk_prefixes=esc_raw.get("low_risk_prefixes", []),
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
