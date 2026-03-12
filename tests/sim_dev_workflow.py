# tests/sim_dev_workflow.py
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from core.llm_adapter import LLMResponse, ToolCall
from core.shell import UniversalShell


class MockLLMForDev:
  """模拟一个聪明的 LLM，引导完成：查看 -> 备份 -> 修改"""

  def __init__(self):
    self.step = 0

  def chat(self, messages, **kwargs):
    self.step += 1
    if self.step == 1:
      return LLMResponse(text="我要先看看项目里有什么", tool_calls=[
        ToolCall(id="c1", name="list_directory", input={"path": "."})
      ], finish_reason="tool_calls")

    if self.step == 2:
      return LLMResponse(text="发现 main.py，读取内容", tool_calls=[
        ToolCall(id="c2", name="read_file", input={"path": "main.py", "reason": "分析代码"})
      ], finish_reason="tool_calls")

    if self.step == 3:
      return LLMResponse(text="准备修改。先备份，再写入新版本", tool_calls=[
        ToolCall(id="c3", name="backup_file", input={"path": "main.py"}),
        ToolCall(id="c4", name="write_file", input={"path": "main.py", "content": "print('fixed')", "reason": "修复Bug"})
      ], finish_reason="tool_calls")

    return LLMResponse(text="任务完成", tool_calls=[], finish_reason="stop")

  def structured_chat(self, *args, **kwargs):
    return {"is_necessary": True, "reasoning": "测试需要", "alternative": ""}


class TestRealDevWorkflow(unittest.TestCase):
  def setUp(self):
    self.test_dir = tempfile.mkdtemp()
    # 创建一个假项目
    (Path(self.test_dir) / "main.py").write_text("print('buggy code')")
    (Path(self.test_dir) / "roles").mkdir()
    # 拷贝真实的 developer 角色配置
    shutil.copy("roles/developer-v1.yaml", Path(self.test_dir) / "roles/dev.yaml")

    self.old_cwd = os.getcwd()
    os.chdir(self.test_dir)

  def tearDown(self):
    os.chdir(self.old_cwd)
    shutil.rmtree(self.test_dir)

  def test_workflow_execution(self):
    shell = UniversalShell(
        manifest_path="roles/dev.yaml",
        model="mock-model",
        audit_log_dir="./logs",
        memory_dir="./memory"
    )
    # 注入 Mock LLM
    shell._llm = MockLLMForDev()
    shell._escalation.set_llm_call_fn(shell._llm.structured_chat)

    # 模拟运行
    shell.start()

    # 验证结果
    # 1. 验证文件是否真的被修改
    main_content = Path("main.py").read_text()
    self.assertEqual(main_content, "print('fixed')")

    # 2. 验证备份文件是否生成
    backups = list(Path(".").glob("main-*.py"))
    self.assertTrue(len(backups) > 0)

    # 3. 验证审计日志是否产生
    log_files = list(Path("./logs").glob("*.jsonl"))
    self.assertTrue(len(log_files) > 0)
    print(f"\n✅ 集成测试成功：文件已修改，备份已创建，日志已记录。")


if __name__ == "__main__":
  unittest.main()
