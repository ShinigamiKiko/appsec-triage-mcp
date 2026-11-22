from types import SimpleNamespace

import pytest

from appsec_triage_mcp.code import bounded_tools_class, load_core


@pytest.fixture
def tools(tmp_path):
    module = load_core()
    root = tmp_path / "project"
    root.mkdir()
    return bounded_tools_class(module)(SimpleNamespace(), root)


def test_real_agent_reading_and_search(tools):
    (tools.root / "main.py").write_text("def handler():\n    return 'hello'\n")
    assert "1: def handler():" in tools.read("main.py")
    assert "main.py:1:" in tools.search("handler")
    assert tools.resolve("../outside.py") is None


def test_secret_files_and_symlink_reads_are_blocked(tools, tmp_path):
    (tools.root / ".env").write_text("SECRET=hidden")
    assert "hidden" not in tools.read(".env")
    outside = tmp_path / "outside.py"
    outside.write_text("SENSITIVE_VALUE")
    try:
        (tools.root / "link.py").symlink_to(outside)
    except OSError:
        pytest.skip("OS does not permit symlinks")
    assert "SENSITIVE_VALUE" not in tools.read("link.py")
    assert "SENSITIVE_VALUE" not in tools.search("SENSITIVE")
