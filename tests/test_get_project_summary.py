#!/usr/bin/env python3
"""
GetProjectSummaryTool 的单元测试
验证工具的更名、新增文件摘要属性 (fileSize, fileLines) 以及深度限制等功能。
"""

import fnmatch  # <-- New import for robust pattern matching
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path to allow importing core modules
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.tool import GetProjectSummaryTool


# Removed explicit import of PermissionChecker, as MockPermissionChecker is used


# Mock for PermissionChecker - REVISED
class MockPermissionChecker:
  def __init__(self, allowed_patterns=None, denied_patterns=None):
    # Default to allowing all if no specific patterns are given, for convenience in tests.
    self.allowed_patterns = allowed_patterns if allowed_patterns is not None else ["*"]
    self.denied_patterns = denied_patterns if denied_patterns is not None else []
    self.audit_log = []

  def check(self, tool_name, target, permission_type, reason, context):
    # This mock's responsibility is *only* to simulate the permission *policy* check.
    # The tool's own _secure_path (from core.tool.Tool) is responsible for handling
    # 'unsafe' characters like \x00 or path traversal attempts.

    # 1. Check explicit denials first (more specific patterns should take precedence)
    for p in self.denied_patterns:
      if fnmatch.fnmatch(target, p):
        self.audit_log.append({"tool": tool_name, "target": target, "type": permission_type, "status": "denied"})
        return False, f"Denied by mock policy for pattern: {p}"

    # 2. Check explicit allowances
    for p in self.allowed_patterns:
      if fnmatch.fnmatch(target, p):
        self.audit_log.append({"tool": tool_name, "target": target, "type": permission_type, "status": "approved"})
        return True, None

    # 3. Default deny if no explicit allow or deny rule matched
    self.audit_log.append({"tool": tool_name, "target": target, "type": permission_type, "status": "default_denied"})
    return False, "Not explicitly allowed by mock policy."


# Helper to create dummy files and directories
def create_dummy_project_structure(base_path: Path):
  (base_path / "src").mkdir()
  (base_path / "src" / "main.py").write_text("print('hello')\nprint('world')")  # 2 lines
  (base_path / "src" / "utils.py").write_text("# utility file\ndef foo(): pass")  # 2 lines
  (base_path / "docs").mkdir()
  (base_path / "docs" / "README.md").write_text("# Project Readme\n\nSome info.")  # 3 lines
  (base_path / "empty_dir").mkdir()
  (base_path / "binary_file.bin").write_bytes(b'\x00\x01\x02\x03')  # 4 bytes, 0 lines
  (base_path / ".gitignore").write_text("*.log\n")  # hidden file
  (base_path / "temp_backup").mkdir()  # should be ignored by tool
  (base_path / "logs").mkdir()  # should be ignored by tool


def test_get_project_summary_basic():
  print("\n--- Test: Basic project summary ---")
  with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir)
    create_dummy_project_structure(temp_path)

    # Allow all paths within the temp_path
    mock_checker = MockPermissionChecker(allowed_patterns=[str(temp_path) + "/**"])
    tool = GetProjectSummaryTool(mock_checker.check)

    result = tool.execute(path=str(temp_path), max_depth=2, reason="test")

    assert result["status"] == "ok", f"Expected status 'ok', got {result.get('status')} with error {result.get('message')}"
    summary_items = result["data"]["summary_items"]

    # Expecting a flat list of items
    # Note: .gitignore, temp_backup, logs should be excluded by the tool's walk logic.
    expected_names = {
      "src", "main.py", "utils.py",  # src folder contents
      "docs", "README.md",  # docs folder contents
      "empty_dir",  # empty_dir
      "binary_file.bin"  # root file
    }

    found_names = {item["name"] for item in summary_items}

    # Check if all expected items are found
    assert expected_names.issubset(found_names), f"Missing items. Expected: {expected_names}, Found: {found_names}"
    assert len(found_names) == len(expected_names), f"Unexpected items found or duplicate items. Expected count {len(expected_names)}, Found count {len(found_names)}"

    # Check a specific file for fileSize and fileLines
    main_py = next((item for item in summary_items if item["name"] == "main.py"), None)
    assert main_py is not None
    assert main_py["type"] == "file"
    assert main_py["fileSize"] == len("print('hello')\nprint('world')")
    assert main_py["fileLines"] == 2
    print(f"✅ main.py summary correct: size={main_py['fileSize']}, lines={main_py['fileLines']}")

    readme_md = next((item for item in summary_items if item["name"] == "README.md"), None)
    assert readme_md is not None
    assert readme_md["type"] == "file"
    assert readme_md["fileSize"] == len("# Project Readme\n\nSome info.")
    assert readme_md["fileLines"] == 3
    print(f"✅ README.md summary correct: size={readme_md['fileSize']}, lines={readme_md['fileLines']}")

    binary_file = next((item for item in summary_items if item["name"] == "binary_file.bin"), None)
    assert binary_file is not None
    assert binary_file["type"] == "file"
    assert binary_file["fileSize"] == 4
    assert binary_file["fileLines"] == 0  # Binary files should have 0 lines as they can't be decoded
    print(f"✅ binary_file.bin summary correct: size={binary_file['fileSize']}, lines={binary_file['fileLines']}")

    # Check that ignored directories are not present
    assert not any(item["name"] == ".gitignore" for item in summary_items)
    assert not any(item["name"] == "temp_backup" for item in summary_items)
    assert not any(item["name"] == "logs" for item in summary_items)
    print("✅ Ignored directories/files correctly excluded.")

    print("✅ Basic project summary test passed.")


def test_get_project_summary_depth_limit():
  print("\n--- Test: Depth limit ---")
  with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir)
    (temp_path / "level1").mkdir()
    (temp_path / "level1" / "file1.txt").write_text("1")
    (temp_path / "level1" / "level2").mkdir()
    (temp_path / "level1" / "level2" / "file2.txt").write_text("2")
    (temp_path / "level1" / "level2" / "level3").mkdir()
    (temp_path / "level1" / "level2" / "level3" / "file3.txt").write_text("3")

    mock_checker = MockPermissionChecker(allowed_patterns=[str(temp_path) + "/**"])
    tool = GetProjectSummaryTool(mock_checker.check)

    # max_depth=0: only current dir contents
    result_0 = tool.execute(path=str(temp_path), max_depth=0)
    assert result_0["status"] == "ok", f"Depth 0: {result_0.get('message')}"
    names_0 = sorted([item["name"] for item in result_0["data"]["summary_items"]])
    expected_names_0 = ["level1"]
    assert names_0 == expected_names_0, f"max_depth=0 failed. Expected: {expected_names_0}, Got: {names_0}"
    print(f"✅ Depth 0 correct: {names_0}")

    # max_depth=1: current dir contents + one level down
    result_1 = tool.execute(path=str(temp_path), max_depth=1)
    assert result_1["status"] == "ok", f"Depth 1: {result_1.get('message')}"
    names_1 = sorted([item["name"] for item in result_1["data"]["summary_items"]])
    expected_names_1 = ["file1.txt", "level1", "level2"]
    assert names_1 == expected_names_1, f"max_depth=1 failed. Expected: {expected_names_1}, Got: {names_1}"
    print(f"✅ Depth 1 correct: {names_1}")

    # max_depth=2: current dir contents + two levels down
    result_2 = tool.execute(path=str(temp_path), max_depth=2)
    assert result_2["status"] == "ok", f"Depth 2: {result_2.get('message')}"
    names_2 = sorted([item["name"] for item in result_2["data"]["summary_items"]])
    expected_names_2 = ["file1.txt", "file2.txt", "level1", "level2", "level3"]
    assert names_2 == expected_names_2, f"max_depth=2 failed. Expected: {expected_names_2}, Got: {names_2}"
    print(f"✅ Depth 2 correct: {names_2}")

    print("✅ Depth limit test passed.")


def test_get_project_summary_permission_denied_by_mock():
  print("\n--- Test: Permission denied by mock checker ---")
  with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir)
    create_dummy_project_structure(temp_path)

    # Mock checker denies access to temp_path
    mock_checker = MockPermissionChecker(allowed_patterns=[], denied_patterns=[str(temp_path) + "/**"])
    tool = GetProjectSummaryTool(mock_checker.check)

    result = tool.execute(path=str(temp_path), max_depth=2, reason="test")

    assert result["status"] == "error"
    assert result["error_code"] == "PERMISSION_DENIED"
    assert "Denied by mock policy" in result["message"]
    print("✅ Permission denied by mock checker test passed.")


def test_get_project_summary_invalid_path():
  print("\n--- Test: Invalid path handled by tool's _secure_path ---")
  mock_checker = MockPermissionChecker(allowed_patterns=["*"])  # Mock allows everything for policy, to test tool's _secure_path
  tool = GetProjectSummaryTool(mock_checker.check)

  # Path does not exist
  result_non_existent = tool.execute(path="/non/existent/path/xyz", reason="test")
  assert result_non_existent["status"] == "error"
  assert result_non_existent["error_code"] == "NOT_FOUND"
  print("✅ Non-existent path test passed (handled by tool).")

  # Path is unsafe (contains null byte) - this should be caught by tool's _secure_path
  result_unsafe_null = tool.execute(path="path\x00with\x00null", reason="test")
  assert result_unsafe_null["status"] == "error"
  assert result_unsafe_null["error_code"] == "INVALID_PATH"
  assert "不安全或无效" in result_unsafe_null["message"]
  print("✅ Unsafe path (null byte) test passed (handled by tool).")

  if Path("/etc/passwd").exists():
    result_file_not_dir = tool.execute(path="/etc/passwd", reason="test")
    assert result_file_not_dir["status"] == "error"
    assert result_file_not_dir["error_code"] == "NOT_A_DIRECTORY"
    print("✅ Dangerous file path (not a directory) test passed (handled by tool).")
  else:
    print("ℹ️ /etc/passwd does not exist or is not accessible, skipping related test.")


def test_get_project_summary_not_a_directory():
  print("\n--- Test: Path exists but is not a directory ---")
  with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir)
    (temp_path / "file.txt").write_text("content")

    mock_checker = MockPermissionChecker(allowed_patterns=[str(temp_path) + "/**"])
    tool = GetProjectSummaryTool(mock_checker.check)

    result = tool.execute(path=str(temp_path / "file.txt"), reason="test")
    assert result["status"] == "error"
    assert result["error_code"] == "NOT_A_DIRECTORY"
    print("✅ Not a directory test passed (handled by tool).")


def test_get_project_summary_empty_path():
  print("\n--- Test: Empty path ---")
  mock_checker = MockPermissionChecker(allowed_patterns=["*"])
  tool = GetProjectSummaryTool(mock_checker.check)

  result = tool.execute(path="", reason="test")
  assert result["status"] == "error"
  assert result["error_code"] == "INVALID_PATH"
  print("✅ Empty path test passed (handled by tool's _secure_path).")


def main():
  print("🚀 Starting GetProjectSummaryTool unit tests...\n")

  all_tests_passed = True

  test_functions = [
    test_get_project_summary_basic,
    test_get_project_summary_depth_limit,
    test_get_project_summary_permission_denied_by_mock,
    test_get_project_summary_invalid_path,
    test_get_project_summary_not_a_directory,
    test_get_project_summary_empty_path,
  ]

  for test_func in test_functions:
    try:
      test_func()
    except Exception as e:
      print(f"❌ Test '{test_func.__name__}' FAILED: {e}")
      import traceback
      traceback.print_exc()
      all_tests_passed = False
    print("-" * 50)  # Separator for readability

  print("\n--- All GetProjectSummaryTool tests completed ---")
  if all_tests_passed:
    print("🎉 All tests PASSED!")
    sys.exit(0)
  else:
    print("❌ Some tests FAILED!")
    sys.exit(1)


if __name__ == "__main__":
  main()
