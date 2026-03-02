#!/usr/bin/env python3
"""
受控百变智能体 (CVA) v2 — 主入口
用法:
  # 新建 session
  python cva.py --manifest roles/code-reviewer-v1.yaml

  # 恢复历史 session
  python cva.py --manifest roles/code-reviewer-v1.yaml --session <session-id>

  # 列出历史 sessions
  python cva.py --manifest roles/code-reviewer-v1.yaml --list-sessions

  # 切换模型（litellm 格式）
  python cva.py --manifest roles/code-reviewer-v1.yaml --model gpt-4o
  python cva.py --manifest roles/code-reviewer-v1.yaml --model ollama/qwen2.5:14b
  python cva.py --manifest roles/code-reviewer-v1.yaml --model gemini/gemini-2.0-flash
"""

import argparse
import sys
import textwrap

from core.manifest import load_manifest
from core.memory import MemoryStore
from core.shell import UniversalShell


def main():
  parser = argparse.ArgumentParser(
      description="受控百变智能体 (CVA) v2 — Controlled Versatile Agent",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=textwrap.dedent("""
        模型示例（--model 参数，litellm 格式）:
          claude-opus-4-5              Anthropic Claude（默认）
          gpt-4o                       OpenAI GPT-4o
          gemini/gemini-2.0-flash      Google Gemini
          ollama/qwen2.5:14b           本地 Ollama
          deepseek/deepseek-chat        DeepSeek
          groq/llama3-70b-8192          Groq
        """).strip()
  )
  parser.add_argument("--manifest", required=True, help="Role Manifest YAML 文件路径")
  parser.add_argument("--model", default="claude-opus-4-5", help="LiteLLM 格式模型名（默认: claude-opus-4-5）")
  parser.add_argument("--session", default=None, help="恢复指定 session ID 的历史对话")
  parser.add_argument("--list-sessions", action="store_true", help="列出该角色的所有历史 sessions 后退出")
  parser.add_argument("--memory-dir", default="./memory", help="记忆存储目录（默认: ./memory）")
  parser.add_argument("--log-dir", default="./audit-logs", help="审计日志目录（默认: ./audit-logs）")
  parser.add_argument("--max-iterations", type=int, default=100, help="最大推理轮次（默认: 100）")
  parser.add_argument("--max-memory-messages", type=int, default=200, help="内存中最大消息条数（默认: 200）")
  parser.add_argument("--max-token-budget", type=int, default=80000, help="触发上下文截断的 token 估算上限（默认: 80000）")
  args = parser.parse_args()

  # 加载 manifest（用于获取 role_name）
  manifest = load_manifest(args.manifest)

  # --list-sessions 模式
  if args.list_sessions:
    sessions = MemoryStore.list_sessions(args.memory_dir, manifest.role_name)
    if not sessions:
      print(f"角色 [{manifest.role_name}] 暂无历史 sessions。")
    else:
      print(f"\n角色 [{manifest.role_name}] 历史 Sessions（共 {len(sessions)} 个）:")
      print("─" * 80)
      for s in sessions:
        print(f"  ID      : {s.session_id}")
        print(f"  消息数  : {s.message_count}")
        print(f"  更新时间: {s.updated_at}")
        print(f"  摘要    : {s.summary or '（无）'}")
        print("─" * 80)
    sys.exit(0)

  # 正常启动
  shell = UniversalShell(
      manifest_path=args.manifest,
      model=args.model,
      log_dir=args.log_dir,
      memory_dir=args.memory_dir,
      session_id=args.session,
      max_iterations=args.max_iterations,
      max_memory_messages=args.max_memory_messages,
      max_token_budget=args.max_token_budget,
  )

  try:
    shell.start()
  except KeyboardInterrupt:
    print("\n\n[CVA] 收到中断信号，优雅退出...")
    shell.stop("keyboard_interrupt")
    sys.exit(0)


if __name__ == "__main__":
  main()
