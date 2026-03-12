# tests/sim_dev_workflow.py
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# 导入必要的类型
from core.llm_adapter import LLMResponse, ToolCall, CallStats
from core.shell import UniversalShell


class MockLLMForDev:
  """模拟一个聪明的 LLM，引导完成：查看 -> 备份 -> 修改"""

  def __init__(self):
    self.step = 0
    # 必须提供 stats 对象以供系统提示词生成使用
    self.stats = CallStats()

  def chat(self, messages, **kwargs):
    self.step += 1
    self.stats.total_calls += 1

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
    # 返回字典即可，UniversalShell._make_pre_screen_call 会负责将其转换为 PreScreenResult 对象
    return {"is_necessary": True, "reasoning": "测试需要", "alternative": ""}


class TestRealDevWorkflow(unittest.TestCase):
  def setUp(self):
    self.test_dir = tempfile.mkdtemp()
    (Path(self.test_dir) / "main.py").write_text("print('buggy code')")
    (Path(self.test_dir) / "roles").mkdir()
    shutil.copy("roles/developer-v1.yaml", Path(self.test_dir) / "roles/dev.yaml")

    self.old_cwd = os.getcwd()
    os.chdir(self.test_dir)

    # 模拟输入：1. 启动任务 2. 结束确认
    self.original_stdin = sys.stdin
    self.mock_stdin = io.StringIO("\n\n")
    sys.stdin = self.mock_stdin

  def tearDown(self):
    sys.stdin = self.original_stdin
    os.chdir(self.old_cwd)
    shutil.rmtree(self.test_dir)

  def test_workflow_execution(self):
    shell = UniversalShell(
        manifest_path="roles/dev.yaml",
        model="mock-model",
        audit_log_dir="var/logs",
        memory_dir="var/data/memory"
    )

    # 注入 Mock LLM
    shell._llm = MockLLMForDev()

    # 【关键修复】：删除下面这一行
    # shell._escalation.set_llm_call_fn(shell._llm.structured_chat)
    # 理由：UniversalShell 在初始化时已经设置了正确的包装函数，
    # 它会自动调用 shell._llm.structured_chat 并处理 dict 到 object 的转换。

    # 模拟运行
    shell.start()

    # 验证结果
    # 1. 验证文件是否真的被修改
    main_content = Path("main.py").read_text()
    self.assertEqual(main_content, "print('fixed')")

    # 2. 验证备份文件是否生成
    backups = list(Path(".").glob("main-*.py"))
    self.assertTrue(len(backups) > 0, "应该至少生成一个备份文件")

    # 3. 验证审计日志是否产生
    log_files = list(Path("var/logs").glob("*.jsonl"))
    self.assertTrue(len(log_files) > 0, "应该生成审计日志文件")

    print(f"\n✅ 集成测试成功：流程完整执行。")


if __name__ == "__main__":
  unittest.main()
