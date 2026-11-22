import asyncio
import json
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_triage_mcp import server as server_module
from appsec_triage_mcp.jobs import JobError, JobManager, Workspace
from appsec_triage_mcp.scp import SCPError, SCPTarget


def manager_at(tmp_path):
    return JobManager(Workspace(tmp_path, tmp_path / "output", tmp_path))


def test_client_report_and_bundle(tmp_path):
    manager = manager_at(tmp_path)
    saved = manager.save_result("demo", "# Review\n<script>alert(1)</script>")
    output = Path(saved["output_dir"])
    (output / "internal-secret.txt").write_text("must not leave the server")
    assert "<script>" not in (output / "report-review.html").read_text(encoding="utf-8")
    with zipfile.ZipFile(manager.bundle(saved["job_id"])) as bundle:
        assert set(bundle.namelist()) == {"result.json", "report-review.md", "report-review.html"}
        assert json.loads(bundle.read("result.json"))["kind"] == "review"


def test_scp_uses_strict_host_checking_and_no_shell(tmp_path, monkeypatch):
    captured = {}
    bundle = tmp_path / "result.zip"
    bundle.write_bytes(b"zip")

    def run(argv, **kwargs):
        captured.update(argv=argv, options=kwargs)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    result = SCPTarget("192.0.2.10", "appsec", "/srv/results", port=2222).send(bundle, "job", "lab")
    assert captured["argv"][-1] == "appsec@192.0.2.10:/srv/results/result.zip"
    assert "StrictHostKeyChecking=yes" in captured["argv"]
    assert "BatchMode=yes" in captured["argv"]
    assert "-O" not in captured["argv"]
    assert not captured["options"].get("shell")
    assert result["sent"] is True


@pytest.mark.parametrize("changes", [
    {"host": "-oProxyCommand=evil"}, {"host": "host;id"}, {"user": "user@host"},
    {"directory": "/out/$(id)"}, {"directory": "/out/../etc"}, {"port": True},
    {"port": 0}, {"identity_file": "relative.key"},
])
def test_scp_rejects_unsafe_destination(changes):
    data = {"host": "example.com", "user": "appsec", "directory": "/reports", **changes}
    with pytest.raises(SCPError):
        SCPTarget(**data).validate()


def test_named_target_from_file(tmp_path, monkeypatch):
    config = tmp_path / "scp-targets.json"
    config.write_text(json.dumps({"lab": {"host": "example.com", "user": "appsec", "directory": "/reports"}}))
    monkeypatch.setenv("APPSEC_MCP_SCP_TARGETS_FILE", str(config))
    assert SCPTarget.from_env("lab").host == "example.com"
    with pytest.raises(SCPError, match="Unknown SCP target"):
        SCPTarget.from_env("other")


def test_timeout_does_not_claim_delivery_or_expose_command(tmp_path, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("SECRET COMMAND", 120)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(SCPError, match="unconfirmed") as error:
        SCPTarget("example.com", "appsec", "/reports").send(tmp_path / "bundle.zip", "job", "lab")
    assert "SECRET" not in str(error.value)


def test_scp_uses_temporary_private_key_and_cleans_it(tmp_path, monkeypatch):
    key = tmp_path / "mounted-key"
    key.write_text("dummy-test-key")
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"zip")
    seen = []

    def run(argv, **kwargs):
        used_key = Path(argv[argv.index("-i") + 1])
        assert used_key != key
        assert used_key.read_text() == "dummy-test-key"
        seen.append(used_key)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    SCPTarget("example.com", "appsec", "/reports", identity_file=str(key)).send(bundle, "job", "lab")
    assert key.is_file()
    assert not seen[0].exists()


def test_scp_available_via_mcp(tmp_path, monkeypatch):
    manager = manager_at(tmp_path)
    saved = manager.save_result("demo", "Review")
    monkeypatch.setattr(server_module, "_manager", manager)
    monkeypatch.setenv("APPSEC_MCP_SCP_TARGETS_JSON", json.dumps({
        "default": {"host": "example.com", "user": "appsec", "directory": "/reports"}}))
    monkeypatch.delenv("APPSEC_MCP_SCP_TARGETS_FILE", raising=False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    response = asyncio.run(server_module.server.call_tool("appsec_send_scp_result", {"job_id": saved["job_id"]}))
    assert not response.is_error
    assert json.loads(response.content[0].text)["sent"] is True


def test_scan_reports_are_in_root_directory(tmp_path):
    manager = JobManager(Workspace(tmp_path, tmp_path / "out", tmp_path),
                         popen=lambda *a, **k: SimpleNamespace(wait=lambda: 0, poll=lambda: 0))
    started = manager.start("scan", ["scan"])
    output = Path(started["output_dir"])
    (output / "opengrep.sarif").write_text("{}")
    (output / "scan-manifest.json").write_text("{}")
    result = manager.result(started["job_id"])
    assert result["scanner_reports"] == [str(output / "opengrep.sarif")]
    with zipfile.ZipFile(manager.bundle(started["job_id"])) as bundle:
        assert "opengrep.sarif" in bundle.namelist()


def test_artifact_symlink_escape_rejected(tmp_path):
    manager = manager_at(tmp_path)
    saved = manager.save_result("demo", "Review")
    outside = tmp_path / "secret.html"
    outside.write_text("secret")
    path = Path(saved["output_dir"]) / "report-link.html"
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip("OS does not permit symlinks")
    with pytest.raises(JobError, match="job output directory"):
        manager.report_path(saved["job_id"], path.name)
    with pytest.raises(JobError, match="inside the job"):
        manager.report_path(saved["job_id"])
