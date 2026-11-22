import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_triage_mcp import repository_worker
from appsec_triage_mcp.jobs import JobError, JobManager, Workspace
from appsec_triage_mcp.repositories import project_name, repository_urls
from appsec_triage_mcp.repository_worker import run_repository


@pytest.mark.parametrize("value", ["", "a,b,c,d", "https://host/a,", "file:///tmp/repo", "ext::evil",
                                  "https://token@host/a", "https://host/a?token=secret", "--upload-pack=evil"])
def test_invalid_repositories_are_rejected(value):
    with pytest.raises(JobError):
        repository_urls(value)


def test_three_repositories_and_names():
    urls = repository_urls("https://host/team/a.git,git@host:team/b.git,ssh://git@host/team/c.git")
    assert [project_name(url) for url in urls] == ["a", "b", "c"]


@pytest.mark.parametrize("failure", ["none", "clone", "scan", "exception"])
def test_worker_preserves_reports_and_removes_checkout(tmp_path, monkeypatch, failure):
    checkout = tmp_path / "checkout"
    output = tmp_path / "output"
    seen = []

    def run(argv, **kwargs):
        seen.append((argv, kwargs))
        if argv[0] == "git":
            Path(argv[-1]).mkdir()
            (Path(argv[-1]) / "main.py").write_text("print('hello')")
            return SimpleNamespace(returncode=1 if failure == "clone" else 0)

    def scan(source, output, scanners, **kwargs):
        if failure == "exception":
            raise OSError("scanner failed to start")
        assert os.environ["APPSEC_ECOSYSTEMS"] == "pypi"
        (output / "report-scan.html").write_text("<html>result</html>")
        return 2 if failure == "scan" else 0

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(repository_worker, "run_scan", scan)
    monkeypatch.setenv("APPSEC_ECOSYSTEMS", "")
    if failure == "exception":
        with pytest.raises(OSError):
            run_repository("https://host/a.git", checkout, output, ["scan"])
    else:
        code = run_repository("https://host/a.git", checkout, output, ["scan"])
        assert code == {"none": 0, "clone": 1, "scan": 2}[failure]
    assert not checkout.exists()
    assert seen[0][0][-2] == "https://host/a.git"
    if failure not in {"clone", "exception"}:
        assert (output / "report-scan.html").is_file()


def test_batch_reserves_capacity_without_partial_submission(tmp_path):
    finished = threading.Event()

    class Process:
        def wait(self):
            finished.wait(3)
            return 0

        def poll(self):
            return None

    manager = JobManager(Workspace(tmp_path, tmp_path / "out", tmp_path), popen=lambda *a, **k: Process())
    try:
        jobs = manager.start_repositories(["https://host/a", "https://host/b"], ["run"])
        assert len(jobs) == 2
        with pytest.raises(JobError, match="At most 3"):
            manager.start_repositories(["https://host/c", "https://host/d"], ["run"])
        assert len(manager.list()) == 2
    finally:
        finished.set()
    deadline = time.monotonic() + 3
    while any(job["status"] == "running" for job in manager.list()) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert all(job["checkout_cleanup"] == "removed" for job in manager.list())


def test_report_pagination(tmp_path):
    manager = JobManager(Workspace(tmp_path, tmp_path / "out", tmp_path))
    saved = manager.save_result("demo", "Привет")
    page = manager.report(saved["job_id"], offset=1, max_chars=20)
    assert page["next_offset"] == 21
    assert page["truncated"] is True
    assert len(page["text"]) == 20


def test_client_review_releases_retained_checkout(tmp_path):
    class Process:
        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    def popen(argv, **options):
        checkout = Path(argv[argv.index("--checkout") + 1])
        (checkout / "source").mkdir(parents=True)
        return Process()

    manager = JobManager(Workspace(tmp_path, tmp_path / "out", tmp_path), popen=popen)
    job = manager.start_repositories(["https://host/demo.git"], ["scan"], keep_checkout=True)[0]
    deadline = time.monotonic() + 3
    while manager.status(job["job_id"])["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.status(job["job_id"])["checkout_cleanup"] == "retained"
    checkout = tmp_path / ".mcp-checkouts" / job["job_id"]
    assert checkout.exists()
    review = manager.save_result("demo", "Review by the connected client", source_job_id=job["job_id"])
    assert review["job_id"] == job["job_id"]
    assert review["checkout_cleanup"] == "removed"
    assert not checkout.exists()
    assert manager.report_path(job["job_id"]).name == "report-review.html"


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group cancellation; checked inside the Docker image")
def test_cancellation_removes_real_process_checkout(tmp_path):
    def popen(argv, **options):
        checkout = argv[argv.index("--checkout") + 1]
        script = ("import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); p.mkdir(parents=True); "
                  "(p/'ready').write_text('ready'); time.sleep(60)")
        return subprocess.Popen([sys.executable, "-c", script, checkout], **options)

    manager = JobManager(Workspace(tmp_path, tmp_path / "out", tmp_path), popen=popen)
    job = manager.start_repositories(["https://host/a"], ["run"])[0]
    checkout = tmp_path / ".mcp-checkouts" / job["job_id"]
    try:
        deadline = time.monotonic() + 5
        while not (checkout / "ready").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert (checkout / "ready").is_file()
        manager.cancel(job["job_id"])
        deadline = time.monotonic() + 5
        while manager.status(job["job_id"])["checkout_cleanup"] == "pending" and time.monotonic() < deadline:
            time.sleep(0.01)
        assert manager.status(job["job_id"])["checkout_cleanup"] == "removed"
        assert not checkout.exists()
    finally:
        manager.close()
