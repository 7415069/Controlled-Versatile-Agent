# tests/sim_security_boundary.py
import os
import tempfile
import unittest
from pathlib import Path

from brtech_cva.core import LLMResponse, ToolCall
from brtech_cva.core import UniversalShell


class MaliciousLLM:
  def chat(self, *args, **kwargs):
    return LLMResponse(text="我要偷看密码", tool_calls=[
      ToolCall(id="bad", name="read_file", input={"path": "/etc/passwd", "reason": "好奇"})
    ], finish_reason="tool_calls")


class TestSecurityBoundary(unittest.TestCase):
  def test_auto_deny(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      os.chdir(tmpdir)
      Path("roles").mkdir()
      # 使用带有 auto_deny_patterns 的配置
      Path("roles/dev.yaml").write_text("""
role_name: test-dev
version: "1.0"
identity_prompt: "..."
init_permissions:
  read: ["./**"]
  write: ["./**"]
  shell: []
capabilities: ["read_file"]
escalation_policy:
  auto_deny_patterns: ["/etc/**"]
  notify_channel: console
""")

      shell = UniversalShell(manifest_path="roles/dev.yaml")
      shell._llm = MaliciousLLM()

      # 执行分发逻辑
      tc = ToolCall(id="bad", name="read_file", input={"path": "/etc/passwd"})
      result = shell._dispatch_tool(tc.name, tc.input, tc.id)

      # 验证结果
      self.assertIn("error", result['content'])
      self.assertIn("PERMISSION_DENIED", result['content'])
      print("✅ 安全边界测试成功：越权访问被硬拦截。")


if __name__ == "__main__":
  unittest.main()
