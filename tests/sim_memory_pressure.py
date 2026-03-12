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
          max_token_budget=2000  # 故意设置很小
      )

      # 1. 注入一个巨大的文件读取结果（模拟 P0 级大上下文）
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

      # 2. 注入多轮普通对话，撑大历史
      for i in range(10):
        memory.append({"role": "user", "content": f"Keep going {i}"})
        memory.append({"role": "assistant", "content": "I am working..."})

      # 3. 准备发送给 LLM 的消息
      prepared = memory.prepare_for_llm(keep_last_n=2)

      # 4. 验证：最早的那个巨大文件内容是否被“脱水”成了语义骨架
      dehydrated_msg = prepared[0]  # 第一个消息是 tool_msg
      content_data = json.loads(dehydrated_msg['content'])

      self.assertTrue(content_data['data']['is_skeleton'] or content_data['data']['is_dehydrated'])
      self.assertLess(len(dehydrated_msg['content']), 500)  # 原本几千个字符，现在应该很小

      print(f"✅ 内存压测成功：巨大消息已被脱水。原始大小: {len(large_content)} -> 压缩后: {len(dehydrated_msg['content'])}")


if __name__ == "__main__":
  unittest.main()
