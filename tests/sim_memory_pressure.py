# tests/sim_memory_pressure.py
import json
import tempfile
import unittest

from core.memory import MemoryStore


class TestMemoryOptimization(unittest.TestCase):
  def test_dehydration_logic(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      memory = MemoryStore(
          memory_dir=tmpdir,
          role_name="tester",
          max_token_budget=20000  # 修复：调高预算，防止消息被 _maybe_trim 物理删除
      )

      # 1. 注入一个巨大的文件读取结果
      large_content = "def heavy_function():\n" + ("    print('data')\n" * 500)
      tool_msg = {
        "role": "tool",
        "tool_call_id": "tc1",
        "content": json.dumps({
          "status": "ok",
          "data": {
            "artifact_type": "file_content",
            "content": large_content,
            "metadata": {"path": "heavy.py"},
            "can_dehydrate": True
          }
        })
      }
      memory.append(tool_msg)

      # 2. 注入多轮普通对话，将 tool_msg 推入“历史区”
      for i in range(10):
        memory.append({"role": "user", "content": f"Keep going {i}"})
        memory.append({"role": "assistant", "content": "I am working..."})

      # 3. 准备发送给 LLM 的消息 (keep_last_n=2 确保 index 0 的消息处于脱水区)
      prepared = memory.prepare_for_llm(keep_last_n=2)

      # 4. 验证：通过 tool_call_id 找到目标消息
      dehydrated_msg = next((m for m in prepared if m.get('tool_call_id') == 'tc1'), None)

      self.assertIsNotNone(dehydrated_msg, "目标工具消息不应被裁剪删除")
      content_data = json.loads(dehydrated_msg['content'])

      # 验证脱水标记
      self.assertTrue(content_data['data'].get('is_skeleton') or content_data['data'].get('is_dehydrated'))
      self.assertLess(len(dehydrated_msg['content']), 1000)

      print(f"✅ 内存压测成功：巨大消息已被脱水。")


if __name__ == "__main__":
  unittest.main()
