import json
from pathlib import Path

import pytest

from appsec_triage_mcp.jobs import JobError, JobManager, Workspace


class FakeProcess:
    def __init__(self, returncode=0):
        self.pid = 12345
        self.returncode = returncode
        self.terminated = False

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.terminated = True
        self.returncode = -9


def workspace(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    output.mkdir()
    return Workspace(source, output, tmp_path, "agent-python")


def test_source_path_rejects_escape(tmp_path):
    manager = JobManager(workspace(tmp_path))

    with pytest.raises(JobError, match="must stay inside"):
        manager.source_path("../outside")


def test_findings_must_be_inside_source_or_output(tmp_path):
    manager = JobManager(workspace(tmp_path))
    outside = tmp_path / "findings.sarif"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(JobError, match="configured source/output roots"):
        manager.findings_path(str(outside))


def test_start_builds_cli_argv_and_isolated_output(tmp_path):
    calls = []
    process = FakeProcess()

    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return process

    manager = JobManager(workspace(tmp_path), popen=popen)
    result = manager.start("scan", ["scan", str(tmp_path / "source"), "-o", "{out}", "-s", "opengrep"])

    argv, options = calls[0]
    assert argv[:3] == ["agent-python", "-m", "appsec_triage_mcp.scanning"]
    assert argv[3] == "scan"
    assert argv[7:] == ["-s", "opengrep"]
    assert result["output_dir"] in argv
    assert result["status"] == "succeeded"
    assert result["exit_code"] == 0
    assert options["cwd"] == tmp_path
    assert options["stderr"] is not None


def test_finding_selects_job_review_context_after_scan(tmp_path, monkeypatch):
    from appsec_triage_mcp import server

    manager = JobManager(workspace(tmp_path), popen=lambda *args, **kwargs: FakeProcess())
    monkeypatch.setattr(server, "_manager", manager)
    job = manager.start("scan", ["scan", ".", "-o", "{out}"])
    output = Path(job["output_dir"])
    summary = output / "summary-scan.json"
    summary.write_text("{}")
    assert manager.review_context(job["job_id"]) == {}
    summary.write_text(json.dumps({"review_context": {"ecosystems": ["npm"], "stacks": ["express"]}}))
    (output / "findings-scan.jsonl").write_text(json.dumps({"cwe": "CWE-79", "kind": "dependency"}))
    finding = server.appsec_job_findings(job["job_id"])["findings"][0]
    data = server.appsec_get_review_instructions(**finding["review_arguments"])
    assert {"prompts/default/sca.md", "prompts/default/injection.md", "prompts/stacks/express.md",
            "prompts/context/npm.md"} <= set(data["layers"])


def test_log_paging_and_structured_result(tmp_path):
    manager = JobManager(workspace(tmp_path), popen=lambda *args, **kwargs: FakeProcess())
    started = manager.start("triage", ["triage", "input.sarif", "-o", "{out}"])
    output = Path(started["output_dir"])
    (output / "summary-llm.json").write_text(json.dumps({"verdicts": {"confirmed": 1}}), encoding="utf-8")
    (output / "report-llm.html").write_text("report", encoding="utf-8")
    Path(started["log_file"]).write_text("abcdef", encoding="utf-8")

    page = manager.log(started["job_id"], offset=2, max_chars=3)
    result = manager.result(started["job_id"])

    assert page == {
        "job_id": started["job_id"],
        "offset": 2,
        "next_offset": 5,
        "total_chars": 6,
        "truncated": True,
        "text": "cde",
    }
    assert result["summaries"][0]["data"]["verdicts"]["confirmed"] == 1
    assert result["reports"] == [str(output / "report-llm.html")]


def test_project_name_and_report_selection(tmp_path):
    manager = JobManager(workspace(tmp_path), popen=lambda *args, **kwargs: FakeProcess())
    started = manager.start(
        "scan",
        ["scan", str(tmp_path / "source"), "-o", "{out}"],
        project="gf-api-gateway",
    )
    output = Path(started["output_dir"])
    (output / "report-llm.html").write_text("english", encoding="utf-8")
    (output / "report-llm-ru.html").write_text("russian", encoding="utf-8")

    assert started["project"] == "gf-api-gateway"
    assert manager.report_path(started["job_id"]) == output / "report-llm-ru.html"
    assert manager.report_path(started["job_id"], "report-llm.html") == output / "report-llm.html"

    with pytest.raises(JobError, match="not a path"):
        manager.report_path(started["job_id"], "../outside.html")


def test_start_failure_is_returned_as_job_state(tmp_path):
    def fail(*args, **kwargs):
        raise OSError("missing executable")

    manager = JobManager(workspace(tmp_path), popen=fail)

    result = manager.start("doctor", ["doctor"])

    assert result["status"] == "failed"
    assert "missing executable" in result["error"]
