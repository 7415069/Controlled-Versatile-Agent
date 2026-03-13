#!/usr/bin/env python3
"""
性能测试脚本 - 验证优化效果
"""

import sys
import time
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from brtech_cva.core import PermissionChecker
from brtech_cva.core import MemoryStore
from brtech_cva.core import Permissions
import tempfile


def test_permission_cache_performance():
    """测试权限缓存性能"""
    print("🧪 测试权限缓存性能...")

    perms = Permissions(
        read=["/tmp/test/*", "/var/log/*", "/home/user/*"],
        write=["/tmp/test/*"],
        shell=["ls", "cat", "grep"]
    )

    checker = PermissionChecker(perms)

    # 测试路径
    test_paths = [
        "/tmp/test/file1.txt",
        "/tmp/test/file2.txt",
        "/var/log/app.log",
        "/home/user/config.json",
        "/tmp/test/subdir/file3.txt",
    ]

    # 第一次调用（缓存未命中）
    start = time.time()
    for _ in range(100):
        for path in test_paths:
            checker.can_read(path)
    first_time = time.time() - start

    # 第二次调用（缓存命中）
    start = time.time()
    for _ in range(100):
        for path in test_paths:
            checker.can_read(path)
    second_time = time.time() - start

    # 获取缓存统计
    snapshot = checker.snapshot()
    cache_stats = snapshot["cache_stats"]

    print(f"  第一次调用（缓存未命中）: {first_time:.4f}s")
    print(f"  第二次调用（缓存命中）: {second_time:.4f}s")
    print(f"  性能提升: {(first_time / second_time):.2f}x")
    print(f"  缓存统计: {cache_stats}")

    # 验证性能提升
    assert second_time < first_time, "缓存应该提升性能"
    assert cache_stats["hit_rate"] != "0%", "应该有缓存命中"

    print("✅ 权限缓存性能测试通过\n")


def test_token_estimate_performance():
    """测试 Token 估算性能"""
    print("🧪 测试 Token 估算性能...")

    with tempfile.TemporaryDirectory() as temp_dir:
        # 创建内存存储
        memory = MemoryStore(
            memory_dir=temp_dir,
            role_name="test-role",
            max_messages=100,
            max_token_budget=50000,
        )

        # 添加测试消息
        for i in range(50):
            memory.append({
                "role": "user",
                "content": f"测试消息 {i}，这是一段较长的内容用于测试 token 估算性能。" * 10
            })

        # 第一次调用（缓存未命中）
        start = time.time()
        for _ in range(100):
            memory.token_estimate()
        first_time = time.time() - start

        # 第二次调用（缓存命中）
        start = time.time()
        for _ in range(100):
            memory.token_estimate()
        second_time = time.time() - start

        print(f"  第一次调用（缓存未命中）: {first_time:.4f}s")
        print(f"  第二次调用（缓存命中）: {second_time:.4f}s")
        print(f"  性能提升: {(first_time / second_time):.2f}x")

        # 验证性能提升
        assert second_time < first_time, "缓存应该提升性能"

        memory.close()

    print("✅ Token 估算性能测试通过\n")


def test_dangerous_command_detection():
    """测试危险命令检测性能"""
    print("🧪 测试危险命令检测性能...")

    perms = Permissions(
        read=[],
        write=[],
        shell=["ls", "cat", "grep", "find"]
    )

    checker = PermissionChecker(perms)

    # 测试命令
    test_commands = [
        "ls -la",
        "cat file.txt",
        "grep pattern file.txt",
        "find /tmp -name '*.log'",
        "ls -la /tmp",
    ] * 20  # 重复20次

    # 测试性能
    start = time.time()
    for cmd in test_commands:
        checker.can_shell(cmd)
    elapsed = time.time() - start

    print(f"  检测 {len(test_commands)} 个命令耗时: {elapsed:.4f}s")
    print(f"  平均每个命令: {elapsed / len(test_commands) * 1000:.2f}ms")

    # 验证性能（应该很快）
    assert elapsed < 0.1, "危险命令检测应该很快"

    print("✅ 危险命令检测性能测试通过\n")


def test_path_matching_performance():
    """测试路径匹配性能"""
    print("🧪 测试路径匹配性能...")

    perms = Permissions(
        read=["/tmp/*", "/var/log/*", "/home/user/*", "/etc/config/*"],
        write=[],
        shell=[]
    )

    checker = PermissionChecker(perms)

    # 测试路径
    test_paths = [
        "/tmp/test/file1.txt",
        "/tmp/test/file2.txt",
        "/var/log/app.log",
        "/home/user/config.json",
        "/etc/config/settings.yaml",
        "/tmp/subdir/file3.txt",
        "/var/log/nginx/access.log",
    ] * 50  # 重复50次

    # 测试性能
    start = time.time()
    for path in test_paths:
        checker.can_read(path)
    elapsed = time.time() - start

    print(f"  检查 {len(test_paths)} 个路径耗时: {elapsed:.4f}s")
    print(f"  平均每个路径: {elapsed / len(test_paths) * 1000:.2f}ms")

    # 验证性能
    assert elapsed < 0.5, "路径匹配应该很快"

    print("✅ 路径匹配性能测试通过\n")


def main():
    """运行所有性能测试"""
    print("🚀 开始性能测试\n")
    print("=" * 60)

    try:
        test_permission_cache_performance()
        test_token_estimate_performance()
        test_dangerous_command_detection()
        test_path_matching_performance()

        print("=" * 60)
        print("🎉 所有性能测试通过！")
        print("\n📊 性能优化总结:")
        print("1. ✅ 权限缓存显著提升性能")
        print("2. ✅ Token 估算缓存有效减少计算")
        print("3. ✅ 危险命令检测优化（集合查找）")
        print("4. ✅ 路径匹配优化（提前返回）")

    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
