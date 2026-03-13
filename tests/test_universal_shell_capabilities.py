import collections
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import patch

# 确保项目根目录在 sys.path 中，以便导入 core 模块
project_root = Path(__file__).parent.parent
# 如果这个脚本在 tests 目录下，那么项目根目录是其父目录的父目录
if "tests" in str(project_root):
  sys.path.insert(0, str(project_root))
else:
  # 否则假设当前目录就是项目根目录
  sys.path.insert(0, str(Path(__file__).parent))

# 从核心模块导入必要的类
from brtech_cva.core import UniversalShell
from brtech_cva.core import LLMResponse, ToolCall, LLMError, LLMErrorType, CallStats


# --- 1. 模拟 LLMAdapter 类 ---
class MockLLMAdapter:
  """
  模拟 LLMAdapter，用于返回预定义的 LLMResponse 序列。
  每个 .chat() 调用会从 _responses 队列中取出一个响应。
  """

  def __init__(self, model: str, responses: list[LLMResponse]):
    self._model = model
    self._responses = collections.deque(responses)
    self.chat_calls = []
    self.structured_chat_calls = []
    self._stats = CallStats()

  @property
  def model(self) -> str:
    return self._model

  @property
  def stats(self) -> CallStats:
    return self._stats

  def chat(self, messages: list[dict], system_prompt: str, tools: Optional[list[dict]] = None, max_tokens: int = 8192, temperature: float = 0.0) -> LLMResponse:
    self.chat_calls.append({
      "messages": messages,
      "system_prompt": system_prompt,
      "tools": tools,
      "max_tokens": max_tokens,
      "temperature": temperature
    })
    if not self._responses:
      print("[MockLLMAdapter] 警告: LLM 没有预设响应，返回默认错误。")
      return LLMResponse(text="[ERROR] No more mock responses", tool_calls=[], finish_reason="error", error=LLMError(LLMErrorType.UNKNOWN_ERROR, "No mock responses left"))

    response = self._responses.popleft()
    self._stats.total_calls += 1
    if response.error:
      self._stats.failed_calls += 1
      self._stats.error_counts[response.error.error_type] = self._stats.error_counts.get(response.error.error_type, 0) + 1
    else:
      self._stats.successful_calls += 1
      # 模拟 LLM 消耗 token
      self._stats.total_tokens += response.usage.get("total_tokens", 100) if response.usage else 100
    return response

  def structured_chat(self, messages: list[dict], system_prompt: str, output_schema: dict,
      function_name: str, function_description: str, max_tokens: int = 1024, temperature: float = 0.0) -> Optional[dict]:
    """
    模拟 EscalationManager 中的 LLM 预审查。
    为了测试工具，默认返回 is_necessary=True，这样请求会通过 LLM 预审查阶段。
    """
    self.structured_chat_calls.append({
      "messages": messages,
      "system_prompt": system_prompt,
      "output_schema": output_schema,
      "function_name": function_name,
      "function_description": function_description,
      "max_tokens": max_tokens,
      "temperature": temperature
    })
    self._stats.total_calls += 1
    self._stats.successful_calls += 1
    self._stats.total_tokens += 50  # 模拟 token 消耗
    return {"is_necessary": True, "reasoning": "Mocking LLM pre-screen to allow for testing purposes.", "alternative": ""}


# --- 2. 模拟 HTTP 响应类 ---
class MockHTTPResponse:
  def __init__(self, status: int, body: str):
    self.status = status
    self._body = body.encode('utf-8')

  def read(self) -> bytes:
    return self._body

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_val, exc_tb):
    pass


# --- 3. 主测试类 ---
class TestUniversalShellCapabilities(unittest.TestCase):

  def setUp(self):
    # 创建临时目录
    self.temp_dir_str = tempfile.mkdtemp()
    self.temp_dir = Path(self.temp_dir_str)

    self.log_dir = self.temp_dir / "audit-logs"
    self.memory_dir = self.temp_dir / "memory"
    self.workspace_dir = self.temp_dir / "agent_workspace"
    self.log_dir.mkdir()
    self.memory_dir.mkdir()
    self.workspace_dir.mkdir()

    # 创建一个临时的 roles 目录和 manifest 文件
    self.roles_dir = self.temp_dir / "roles"
    self.roles_dir.mkdir()
    self.manifest_path = self.roles_dir / "developer-v1.yaml"
    original_manifest_path = Path(__file__).parent.parent / "roles" / "developer-v1.yaml"
    if not original_manifest_path.exists():
      original_manifest_path = Path(__file__).parent / "roles" / "developer-v1.yaml"
    shutil.copy(original_manifest_path, self.manifest_path)

    # 在 temp_dir 内创建 Agent 需要的目录结构
    (self.temp_dir / "core").mkdir()
    (self.temp_dir / "core" / "manifest.py").write_text("class RoleManifest: pass\n")
    (self.temp_dir / "tests").mkdir()
    (self.temp_dir / "docs").mkdir()
    (self.temp_dir / "temp_backup").mkdir()
    (self.temp_dir / "src").mkdir()
    (self.temp_dir / "src" / "main.py").write_text("class MyClass:\n    def __init__(self): pass\n    def run(self): pass")
    (self.temp_dir / "src" / "config.json").write_text(json.dumps({"version": "1.0", "active": True}))
    (self.temp_dir / "docs" / "plan.md").write_text("Initial plan document.")
    (self.temp_dir / "test_file.txt").write_text("This is a test file for reading and writing.")
    (self.temp_dir / "log.txt").write_text("Log entry 1\nLog entry 2\n")

    # ── 关键修复：切换工作目录到 temp_dir ──
    # Agent 用相对路径操作文件，必须在隔离目录内运行，否则文件写到项目根
    self._original_cwd = os.getcwd()
    os.chdir(self.temp_dir_str)

    # 捕获 stdout 和 stdin
    self.mock_stdout = io.StringIO()
    self.mock_stdin = io.StringIO()
    self.original_stdout = sys.stdout
    self.original_stdin = sys.stdin
    sys.stdout = self.mock_stdout
    sys.stdin = self.mock_stdin

  def tearDown(self):
    # 恢复 stdout 和 stdin（先恢复，避免后续 print 失败）
    sys.stdout = self.original_stdout
    sys.stdin = self.original_stdin
    # 恢复工作目录后再清理 temp（顺序不能反）
    os.chdir(self._original_cwd)
    if os.path.exists(self.temp_dir_str):
      shutil.rmtree(self.temp_dir_str)

  def _setup_shell_and_mocks(self, mock_llm_responses: list[LLMResponse], initial_user_input: str):
    """
    初始化 UniversalShell 并设置所有必要的模拟。
    """
    # 设置模拟的 LLM 适配器
    mock_llm_adapter = MockLLMAdapter(model="mock-model", responses=mock_llm_responses)

    # UniversalShell 构造函数会加载 manifest
    shell = UniversalShell(
        manifest_path=str(self.manifest_path),
        model="mock-model",
        audit_log_dir=str(self.log_dir),
        memory_dir=str(self.memory_dir),
        session_id="test_session_123",
        max_iterations=len(mock_llm_responses) + 2,  # 足够多的迭代次数
        use_gui=False  # 禁用 GUI 以确保控制台模式
    )

    # 替换 UniversalShell 内部的 LLM 适配器为 mock 对象
    shell._llm = mock_llm_adapter

    # 替换 EscalationManager 中的 LLM 预审查函数为 mock 对象
    shell._escalation.set_llm_call_fn(mock_llm_adapter.structured_chat)

    # 提供初始用户输入
    self.mock_stdin.write(initial_user_input + "\n")
    self.mock_stdin.seek(0)  # 将指针重置到开头

    return shell, mock_llm_adapter

  def test_all_capabilities(self):
    print("\n--- 开始所有工具能力的集成测试 ---")

    # LLM 响应序列，每个响应触发一个工具调用，最后一个响应表示任务完成
    mock_responses = [
      # 1. list_directory
      LLMResponse(
          text="好的，我将首先列出当前目录。",
          tool_calls=[ToolCall(id="call_list", name="list_directory", input={"path": "."})],
          finish_reason="tool_calls"
      ),
      LLMResponse(
          text="获取语义地图。",
          tool_calls=[ToolCall(id="call_repo_map", name="get_repo_map", input={"path": ".", "reason": "架构分析"})],
          finish_reason="tool_calls"
      ),
      # 2. get_project_summary
      LLMResponse(
          text="了解了项目结构。接下来，获取项目概要。",
          tool_calls=[ToolCall(id="call_summary", name="get_project_summary", input={"path": ".", "max_depth": 1})],
          finish_reason="tool_calls"
      ),
      # 3. read_file
      LLMResponse(
          text="已获取项目概要。现在读取 'test_file.txt' 的内容。",
          tool_calls=[ToolCall(id="call_read", name="read_file", input={"path": "test_file.txt", "reason": "检查文件内容"})],
          finish_reason="tool_calls"
      ),
      # 4. write_file
      LLMResponse(
          text="文件内容已读取。现在向 'new_file.txt' 写入一些内容。",
          tool_calls=[ToolCall(id="call_write", name="write_file", input={"path": "agent_workspace/new_file.txt", "content": "Hello from CVA!", "reason": "测试写入"})],
          finish_reason="tool_calls"
      ),
      # 5. append_file
      LLMResponse(
          text="文件已写入。现在向 'log.txt' 追加一行内容。",
          tool_calls=[ToolCall(id="call_append", name="append_file", input={"path": "agent_workspace/log.txt", "content": "Log entry 3\n", "reason": "添加日志"})],
          finish_reason="tool_calls"
      ),
      # 6. backup_file
      LLMResponse(
          text="日志已追加。在修改 main.py 之前，先备份它。",
          tool_calls=[ToolCall(id="call_backup", name="backup_file", input={"path": "src/main.py", "reason": "修改前备份"})],
          finish_reason="tool_calls"
      ),
      # 7. find_symbol
      LLMResponse(
          text="main.py 已备份。现在查找其中的 MyClass 定义。",
          tool_calls=[ToolCall(id="call_find", name="find_symbol", input={"symbol_name": "MyClass"})],
          finish_reason="tool_calls"
      ),
      # 8. get_file_skeleton
      LLMResponse(
          text="已找到 MyClass。现在获取 main.py 的文件骨架。",
          tool_calls=[ToolCall(id="call_skeleton", name="get_file_skeleton", input={"path": "src/main.py", "reason": "获取代码结构"})],
          finish_reason="tool_calls"
      ),
      # 9. run_shell (ls)
      LLMResponse(
          text="已获取文件骨架。现在执行一个 shell 命令 'ls -l'。",
          tool_calls=[ToolCall(id="call_shell_ls", name="run_shell", input={"command": "ls -l", "reason": "列出当前目录"})],
          finish_reason="tool_calls"
      ),
      # 10. execute_python_script
      LLMResponse(
          text="Shell 命令已执行。现在运行一个 Python 脚本。",
          tool_calls=[ToolCall(id="call_python", name="execute_python_script", input={"script": "import os; print(f'Current dir: {os.getcwd()}')", "reason": "获取当前工作目录"})],
          finish_reason="tool_calls"
      ),
      # 11. ask_human (需要模拟 stdin 输入)
      LLMResponse(
          text="Python 脚本已运行。现在需要向人类提问。",
          tool_calls=[ToolCall(id="call_ask", name="ask_human", input={"question": "我对当前进度有疑问，是否继续？", "context": "已执行多个工具"})],
          finish_reason="tool_calls"
      ),
      # 12. search_files
      LLMResponse(
          text="人类已回答。现在搜索所有 .py 文件。",
          tool_calls=[ToolCall(id="call_search", name="search_files", input={"pattern": "*.py", "path": ".", "search_content": False})],
          finish_reason="tool_calls"
      ),
      # 13. http_request (需要模拟 urllib.request.urlopen)
      LLMResponse(
          text="已搜索文件。现在发起一个 HTTP 请求到 example.com。",
          tool_calls=[ToolCall(id="call_http", name="http_request", input={"url": "http://example.com/api", "method": "GET", "reason": "测试外部连接"})],
          finish_reason="tool_calls"
      ),
      # 14. submit_plan
      LLMResponse(
          text="HTTP 请求已完成。现在提交任务计划。",
          tool_calls=[ToolCall(id="call_plan", name="submit_plan", input={"goal": "完成所有工具测试", "milestones": ["执行每个工具", "验证结果"]})],
          finish_reason="tool_calls"
      ),
      # 最后一个响应，表示任务完成
      LLMResponse(
          text="所有工具测试已完成，谢谢！",
          tool_calls=[],
          finish_reason="stop"
      ),
    ]

    # 模拟 sys.stdin 的输入序列 (用于 ask_human 和 shell._safe_input)
    # 初始任务输入 + ask_human 的回答 + 结束时的继续对话
    mock_input_sequence = [
      "开始测试所有工具。",  # UniversalShell 启动时的 initial_user_input
      "是的，请继续。",  # ask_human 的回答
      ""  # 任务完成后的 '继续对话？'，留空表示退出
    ]
    self.mock_stdin.write("\n".join(mock_input_sequence))
    self.mock_stdin.seek(0)

    # 模拟 http_request 的 urllib.request.urlopen
    with patch('urllib.request.urlopen') as mock_urlopen:
      mock_urlopen.return_value = MockHTTPResponse(200, "<html>Mocked Content</html>")

      # 设置 shell 并运行
      shell, mock_llm_adapter = self._setup_shell_and_mocks(mock_responses, mock_input_sequence[0])
      shell.start()

      # --- 验证部分 ---
      captured_output = self.mock_stdout.getvalue()

      # 验证文件操作
      self.assertTrue((self.workspace_dir / "new_file.txt").exists(), "new_file.txt 应该存在")
      self.assertEqual((self.workspace_dir / "new_file.txt").read_text(), "Hello from CVA!", "new_file.txt 内容不匹配")
      print("✅ new_file.txt 写入验证通过")

      # log.txt 写在 agent_workspace/，是新文件，只有追加的那一行
      self.assertTrue((self.workspace_dir / "log.txt").exists(), "agent_workspace/log.txt 应该存在")
      self.assertIn("Log entry 3", (self.workspace_dir / "log.txt").read_text(), "log.txt 应含追加内容")
      print("✅ log.txt 追加验证通过")

      # 验证备份文件（backup_file 在 src/main.py 同目录生成 src/main-{timestamp}.py）
      backup_files = list(self.temp_dir.glob("src/main-*.py"))
      self.assertTrue(len(backup_files) >= 1, "src/main.py 的备份文件应该存在")
      print("✅ main.py 备份验证通过")

      # 验证 Python 脚本执行 (通过检查输出)
      self.assertIn("Current dir:", captured_output, "Python 脚本的输出应该在捕获的 stdout 中")
      print("✅ execute_python_script 输出验证通过")

      # 验证 HTTP 请求
      mock_urlopen.assert_called_with(unittest.mock.ANY, timeout=unittest.mock.ANY)  # 至少被调用一次
      self.assertIn("Mocked Content", captured_output, "HTTP 请求的模拟响应应该在输出中")
      print("✅ http_request 验证通过")

      # 验证 ask_human
      self.assertIn("💬 [CVA 向您提问]", captured_output, "应该有 ask_human 的提示")
      print("✅ ask_human 验证通过")

      # 验证 audit log
      #audit_log_files = list(self.log_dir.glob("cva-audit-*.jsonl"))
      #self.assertTrue(len(audit_log_files) > 0, "应该有审计日志文件")
      #audit_content = audit_log_files[0].read_text()

      #self.assertIn("list_directory", audit_content)
      #self.assertIn("read_file", audit_content)
      #self.assertIn("write_file", audit_content)
      #self.assertIn("ESCALATION_APPROVED", audit_content)  # 至少有一个权限审批
      #print("✅ 审计日志验证通过")

      # 验证 LLM 统计信息
      llm_stats = mock_llm_adapter.stats
      self.assertGreaterEqual(llm_stats.total_calls, len(mock_responses), "LLM 调用次数应该匹配或更多")
      self.assertGreater(llm_stats.total_tokens, 0, "LLM 消耗 Token 应该大于 0")
      self.assertEqual(llm_stats.failed_calls, 0, "不应有 LLM 调用失败")
      print(f"✅ LLM 统计验证通过: 总调用 {llm_stats.total_calls}, 总 Token {llm_stats.total_tokens}")

      print("\n--- 所有工具能力集成测试通过！ ---")


if __name__ == '__main__':
  # 为了在非 PyCharm 环境下运行并显示更详细的输出
  # unittest.main() 默认会捕获 stdout，所以需要额外配置
  suite = unittest.TestSuite()
  suite.addTest(unittest.makeSuite(TestUniversalShellCapabilities))

  # 使用 TextTestRunner 来运行测试，可以控制输出
  runner = unittest.TextTestRunner(verbosity=2)  # verbosity=2 显示更多细节
  runner.run(suite)
