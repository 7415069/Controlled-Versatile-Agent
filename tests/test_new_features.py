#!/usr/bin/env python3
"""
测试新增功能：权限撤销、重复申请检测、日志轮转
"""

import os
import sys
import tempfile
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from brtech_cva.core import PermissionChecker
from brtech_cva.core import EscalationManager
from brtech_cva.core import AuditLogger
from brtech_cva.core import Permissions, EscalationPolicy


def test_permission_revoke():
    """测试权限撤销功能"""
    print("🧪 测试权限撤销功能...")
    
    perms = Permissions(
        read=["/tmp/test/*"],
        write=["/tmp/test/*"],
        shell=["ls", "cat"]
    )
    
    checker = PermissionChecker(perms)
    
    # 验证初始权限
    assert checker.can_read("/tmp/test/file.txt"), "初始读权限应该存在"
    assert checker.can_write("/tmp/test/file.txt"), "初始写权限应该存在"
    assert checker.can_shell("ls -la"), "初始Shell权限应该存在"
    print("✅ 初始权限验证通过")
    
    # 撤销读权限
    checker.revoke_read(["/tmp/test/*"])
    assert not checker.can_read("/tmp/test/file.txt"), "读权限应该被撤销"
    print("✅ 读权限撤销成功")
    
    # 撤销写权限
    checker.revoke_write(["/tmp/test/*"])
    assert not checker.can_write("/tmp/test/file.txt"), "写权限应该被撤销"
    print("✅ 写权限撤销成功")
    
    # 撤销Shell权限
    checker.revoke_shell(["ls"])
    assert not checker.can_shell("ls -la"), "Shell权限应该被撤销"
    print("✅ Shell权限撤销成功")
    
    # 测试撤销所有权限
    checker.grant_read(["/tmp/test/*"])
    checker.grant_write(["/tmp/test/*"])
    checker.grant_shell(["ls"])
    
    checker.revoke_all()
    assert not checker.can_read("/tmp/test/file.txt"), "撤销所有后读权限应该不存在"
    assert not checker.can_write("/tmp/test/file.txt"), "撤销所有后写权限应该不存在"
    assert not checker.can_shell("ls -la"), "撤销所有后Shell权限应该不存在"
    print("✅ 撤销所有权限成功")
    
    # 检查权限变更历史
    history = checker.get_permission_history()
    assert len(history) > 0, "应该有权限变更历史"
    print(f"✅ 权限变更历史记录: {len(history)} 条")
    
    print("✅ 权限撤销功能测试通过\n")


def test_audit_log_rotation():
    """测试审计日志轮转功能"""
    print("🧪 测试审计日志轮转功能...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # 创建审计日志器（设置较小的文件大小限制）
        logger = AuditLogger(
            log_dir=temp_dir,
            instance_id="test-instance",
            role_name="test-role",
            max_file_size=1024,  # 1KB
            max_log_age_days=0  # 立即过期
        )
        
        # 写入足够多的日志以触发轮转
        for i in range(100):
            logger.log("TEST_EVENT", {"index": i, "data": "x" * 100})
        
        # 检查是否有多个日志文件
        log_files = [f for f in os.listdir(temp_dir) if f.startswith("cva-audit-")]
        assert len(log_files) >= 2, f"应该有多个日志文件，实际: {len(log_files)}"
        print(f"✅ 日志轮转成功，生成 {len(log_files)} 个文件")
        
        # 测试日志统计
        stats = logger.get_log_stats()
        assert stats["total_files"] >= 2, "统计应该显示多个文件"
        assert stats["total_size_bytes"] > 0, "总大小应该大于0"
        print(f"✅ 日志统计: {stats['total_files']} 文件, {stats['total_size_mb']} MB")
        
        # 测试过期日志清理
        logger._cleanup_old_logs()
        log_files_after = [f for f in os.listdir(temp_dir) if f.startswith("cva-audit-")]
        print(f"✅ 过期日志清理后剩余: {len(log_files_after)} 个文件")
    
    print("✅ 审计日志轮转功能测试通过\n")


def test_duplicate_approval_detection():
    """测试重复申请检测功能"""
    print("🧪 测试重复申请检测功能...")
    
    perms = Permissions(
        read=[],
        write=[],
        shell=[]
    )
    
    checker = PermissionChecker(perms)
    
    policy = EscalationPolicy(
        auto_deny_patterns=["/etc/*"],
        notify_channel="console",
        timeout_seconds=10
    )
    
    # 模拟审计日志函数
    audit_log = []
    def mock_audit(event_type, payload):
        audit_log.append({"event_type": event_type, "payload": payload})
    
    # 创建越权管理器（设置较短的TTL）
    escalation = EscalationManager(
        policy=policy,
        permission_checker=checker,
        audit_log_fn=mock_audit,
        llm_call_fn=None,  # 禁用LLM二次确认
        permission_ttl_hours=24
    )
    
    # 第一次申请（需要人类审批）
    allowed1, msg1 = escalation.check(
        tool_name="read_file",
        target="/tmp/test.txt",
        permission_type="read",
        reason="测试申请"
    )
    # 由于没有LLM调用，应该返回False
    print(f"✅ 第一次申请: allowed={allowed1}")
    
    # 手动批准第一次申请
    pending_requests = escalation._pending
    if pending_requests:
        request_id = list(pending_requests.keys())[0]
        escalation.approve(request_id, ["/tmp/test.txt"])
        print(f"✅ 批准申请: {request_id}")
    
    # 第二次申请相同权限（应该自动批准）
    allowed2, msg2 = escalation.check(
        tool_name="read_file",
        target="/tmp/test.txt",
        permission_type="read",
        reason="重复申请"
    )
    assert allowed2, "重复申请应该自动批准"
    print(f"✅ 重复申请自动批准: allowed={allowed2}")
    
    # 检查审批历史
    history = escalation.get_approval_history()
    assert len(history) >= 1, "应该有审批历史"
    print(f"✅ 审批历史记录: {len(history)} 条")
    
    # 测试过期权限清理
    escalation.cleanup_expired_permissions()
    print("✅ 过期权限清理完成")
    
    print("✅ 重复申请检测功能测试通过\n")


def test_permission_history():
    """测试权限变更历史记录"""
    print("🧪 测试权限变更历史记录...")
    
    perms = Permissions(
        read=[],
        write=[],
        shell=[]
    )
    
    checker = PermissionChecker(perms)
    
    # 授予权限
    checker.grant_read(["/tmp/test/*"])
    checker.grant_write(["/tmp/test/*"])
    checker.grant_shell(["ls"])
    
    # 撤销权限
    checker.revoke_read(["/tmp/test/*"])
    checker.revoke_write(["/tmp/test/*"])
    
    # 检查历史
    history = checker.get_permission_history()
    assert len(history) >= 5, "应该有至少5条变更记录"
    
    # 验证历史记录类型
    change_types = [h["type"] for h in history]
    assert "grant_read" in change_types, "应该有grant_read记录"
    assert "grant_write" in change_types, "应该有grant_write记录"
    assert "grant_shell" in change_types, "应该有grant_shell记录"
    assert "revoke_read" in change_types, "应该有revoke_read记录"
    assert "revoke_write" in change_types, "应该有revoke_write记录"
    
    print(f"✅ 权限变更历史: {len(history)} 条记录")
    print(f"✅ 变更类型: {set(change_types)}")
    
    print("✅ 权限变更历史记录测试通过\n")


def main():
    """运行所有新功能测试"""
    print("🚀 开始新增功能测试\n")
    
    try:
        test_permission_revoke()
        test_audit_log_rotation()
        test_duplicate_approval_detection()
        test_permission_history()
        
        print("🎉 所有新功能测试通过！")
        print("\n📊 新功能总结:")
        print("1. ✅ 权限撤销功能正常")
        print("2. ✅ 审计日志轮转正常")
        print("3. ✅ 重复申请检测正常")
        print("4. ✅ 权限变更历史记录正常")
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
