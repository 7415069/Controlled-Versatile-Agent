# tests/test_permissions.py
import pytest
from hypothesis import given, strategies as st

from core.manifest import Permissions
from core.permissions import PermissionChecker


@pytest.fixture
def checker():
  return PermissionChecker(Permissions(read=["/project/**"], write=["/project/output/*"]))


@given(path=st.text(min_size=1))
def test_path_traversal_prevention(checker, path):
  """路径穿越攻击测试"""
  if ".." in path or path.startswith("/etc") or "/root" in path:
    assert not checker.can_read(path)
    assert not checker.can_write(path)


def test_symlink_attack(checker, tmp_path):
  """符号链接攻击防护"""
  malicious = tmp_path / "evil"
  malicious.write_text("malicious")
  (tmp_path / "link").symlink_to(malicious)
  assert not checker.can_read(str(tmp_path / "link"))  # _safe_resolve_symlinks 会拒绝


def test_cache_clear_on_revoke(checker):
  """权限撤销后缓存必须清空"""
  checker.can_read("/project/src/main.py")  # 命中缓存
  assert checker._cache_misses == 1
  checker.revoke_read(["/project/src/main.py"])
  assert len([k for k in checker._permission_cache if k.startswith("read:")]) == 0

# 更多测试可继续扩展…
