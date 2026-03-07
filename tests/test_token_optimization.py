#!/usr/bin/env python3
"""
Token优化验证测试
验证各项优化是否生效
"""

import shutil
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path to allow importing core modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.tool import ReadFileTool
from core.memory import MemoryStore
from core.shell import UniversalShell


def test_file_read_limit():
  """测试文件读取限制是否降低 (30000字符)"""
  tool = ReadFileTool(check_fn=lambda *args, **kwargs: (True, None))

  assert hasattr(tool, 'MAX_RETURNED_CONTENT_CHARS'), "ReadFileTool 缺少 MAX_RETURNED_CONTENT_CHARS 属性"
  max_chars_limit = tool.MAX_RETURNED_CONTENT_CHARS

  print(f"✓ ReadFileTool MAX_RETURNED_CONTENT_CHARS: {max_chars_limit} 字符")
  assert max_chars_limit == 30000, f"期望 30000，实际 {max_chars_limit}"

  print("✅ 文件读取限制测试通过 (内容字符限制)")


def test_dehydration_cache_ttl():
  """测试脱水缓存时间是否延长"""
  manifest_content = """
role_name: TestRole
version: 1.0
identity_prompt: You are a test agent.
init_permissions:
  read: []
  write: []
  shell: []
capabilities: []
escalation_policy:
  auto_deny_patterns: []
  notify_channel: console
  timeout_seconds: 300
"""
  temp_manifest_dir = None
  try:
    temp_manifest_dir = tempfile.mkdtemp()
    temp_manifest_path = Path(temp_manifest_dir) / 'test_manifest.yaml'
    temp_manifest_path.write_text(manifest_content)

    # Ensure that log_dir and memory_dir are within the temporary directory
    log_dir = Path(temp_manifest_dir) / 'temp_test_logs'
    memory_dir = Path(temp_manifest_dir) / 'temp_test_memory'
    log_dir.mkdir(exist_ok=True)
    memory_dir.mkdir(exist_ok=True)

    shell = UniversalShell(
        manifest_path=str(temp_manifest_path),
        model='claude-opus-4-5',
        audit_log_dir=str(log_dir),
        memory_dir=str(memory_dir),
    )

    print(f"✓ 脱水缓存 TTL: {shell._DEHYDRATION_CACHE_TTL} 秒")
    assert shell._DEHYDRATION_CACHE_TTL == 60.0, f"期望 60.0，实际 {shell._DEHYDRATION_CACHE_TTL}"
    print("✅ 脱水缓存时间测试通过")

    shell.stop()
  finally:
    if temp_manifest_dir and Path(temp_manifest_dir).exists():
      shutil.rmtree(temp_manifest_dir)


def test_token_cache_ttl():
  """测试token缓存时间是否延长"""
  temp_dir = tempfile.mkdtemp()
  try:
    memory = MemoryStore(
        memory_dir=temp_dir,
        role_name='test_role',
        max_messages=100,
        max_token_budget=50000,  # This is the new default expected by the prompt
    )

    print(f"✓ Token 缓存 TTL: {memory._TOKEN_CACHE_TTL} 秒")
    assert memory._TOKEN_CACHE_TTL == 60.0, f"期望 60.0，实际 {memory._TOKEN_CACHE_TTL}"
    print("✅ Token缓存时间测试通过")

    memory.close()
  finally:
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_keep_last_n():
  """测试保留消息数是否减少"""
  # The 'keep_last_n' parameter is passed to MemoryStore.prepare_for_llm
  # by UniversalShell. We will check the call site in UniversalShell.
  with open('./core/shell.py', 'r', encoding='utf-8') as f:
    content = f.read()

  # Search for the specific line where prepare_for_llm is called with keep_last_n=3
  assert 'messages_to_send = self._memory.prepare_for_llm(keep_last_n=3)' in content, "未找到 'messages_to_send = self._memory.prepare_for_llm(keep_last_n=3)'"
  print("✓ 保留消息数: 3 条 (在 MemoryStore.prepare_for_llm 方法调用中)")
  print("✅ 保留消息数测试通过")


def test_dehydration_threshold():
  """测试脱水触发阈值是否降低 (逻辑转移到 MemoryStore)"""
  # Verify _should_dehydrate is no longer in shell.py
  with open('./core/shell.py', 'r', encoding='utf-8') as f:
    shell_content = f.read()
  assert "_should_dehydrate" not in shell_content, "shell.py 中不应再有 _should_dehydrate 方法"
  print("✓ _should_dehydrate 方法已从 shell.py 移除")

  # Verify dehydration logic is now in MemoryStore.prepare_for_llm and is based on history position
  with open('./core/memory.py', 'r', encoding='utf-8') as f:
    memory_content = f.read()
  assert "archive_threshold" in memory_content and "active_threshold" in memory_content, "MemoryStore.prepare_for_llm 中应有历史消息阈值逻辑"
  assert '"artifact_type": "file_content"' in memory_content, "MemoryStore.prepare_for_llm 应处理 file_content"
  print("✓ 脱水逻辑已转移到 MemoryStore.prepare_for_llm，基于历史位置处理 file_content")
  print("✅ 脱水触发阈值（逻辑转移）测试通过")


def test_main_token_budget():
  """测试主入口默认token预算是否降低 (MemoryStore 默认 50000)"""
  # This test checks the default of MemoryStore's max_token_budget.
  # The prompt implies UniversalShell/MemoryStore default should be 50000.

  temp_dir = tempfile.mkdtemp()
  try:
    memory = MemoryStore(
        memory_dir=temp_dir,
        role_name='test_role',
    )
    print(f"✓ MemoryStore 默认 max_token_budget: {memory._max_token_budget}")
    assert memory._max_token_budget == 50000, f"MemoryStore 默认 max_token_budget 期望 50000，实际 {memory._max_token_budget}"
    print("✅ Token预算测试通过")
    memory.close()
  finally:
    shutil.rmtree(temp_dir, ignore_errors=True)


def main():
  """运行所有测试"""
  print("=" * 60)
  print("Token优化验证测试")
  print("=" * 60)
  print()

  tests = [
    ("文件读取限制", test_file_read_limit),
    ("脱水缓存时间", test_dehydration_cache_ttl),
    ("Token缓存时间", test_token_cache_ttl),
    ("保留消息数", test_keep_last_n),
    ("脱水触发阈值", test_dehydration_threshold),
    ("主入口Token预算", test_main_token_budget),
  ]

  passed = 0
  failed = 0

  for name, test_func in tests:
    try:
      print(f"\n🔍 测试: {name}")
      print("-" * 40)
      test_func()
      passed += 1
    except Exception as e:
      print(f"❌ 测试失败: {e}")
      failed += 1
      import traceback
      traceback.print_exc()

  print()
  print("=" * 60)
  print(f"测试结果: {passed} 通过, {failed} 失败")
  print("=" * 60)

  return failed == 0


if __name__ == "__main__":
  success = main()
  sys.exit(0 if success else 1)
