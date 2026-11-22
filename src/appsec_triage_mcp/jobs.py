"""Background AppSec Triage jobs exposed through MCP."""

from __future__ import annotations

import html
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class JobError(ValueError):
    """An MCP job request is invalid or names an unknown job."""


@dataclass
class Job:
    id: str
    kind: str
    output_dir: Path
    log_path: Path
    started_at: float
    project: str = ""
    process: subprocess.Popen | None = None
    finished_at: float | None = None
    returncode: int | None = None
    error: str = ""
    cancelled: bool = False
    repository: str = ""
    checkout_dir: Path | None = None
    cleanup: str = "not_needed"
    waiter: threading.Thread | None = None
    keep_checkout: bool = False


@dataclass(frozen=True)
class Workspace:
    source_root: Path
    output_root: Path
    runtime_root: Path = Path(__file__).resolve().parent.parent
    python_executable: str = sys.executable

    @classmethod
    def from_env(cls) -> Workspace:
        source = os.environ.get("APPSEC_MCP_SOURCE_ROOT")
        output = os.environ.get("APPSEC_MCP_OUTPUT_ROOT")
        if not source or not output:
            raise JobError("Set APPSEC_MCP_SOURCE_ROOT and APPSEC_MCP_OUTPUT_ROOT before starting AppSec MCP jobs.")
        return cls(
            Path(source).expanduser().resolve(),
            Path(output).expanduser().resolve(),
        )


class JobManager:
    def __init__(self, workspace: Workspace, popen=None) -> None:
        self.workspace = workspace
        self._popen = popen or subprocess.Popen
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()

    def source_path(self, value: str = ".") -> Path:
        path = self._inside(value, self.workspace.source_root, "source")
        if not path.is_dir():
            raise JobError(f"Source directory does not exist: {path}")
        return path

    def findings_path(self, value: str) -> Path:
        if not value:
            raise JobError("findings must name a SARIF/JSONL file or a findings directory")
        path = Path(value).expanduser()
        candidates = (
            [path.resolve()]
            if path.is_absolute()
            else [
                (self.workspace.output_root / path).resolve(),
                (self.workspace.source_root / path).resolve(),
            ]
        )
        for candidate in candidates:
            allowed = (
                self.workspace.output_root
                if self.workspace.output_root in (candidate, *candidate.parents)
                else self.workspace.source_root
            )
            try:
                resolved = self._inside(str(candidate), allowed, "findings")
            except JobError:
                continue
            if resolved.exists():
                return resolved
        raise JobError("Findings must be an existing file or directory inside the configured source/output roots")

    def start(self, kind: str, arguments: list[str], project: str | None = None, *,
              repository: str = "", job_id: str | None = None, keep_checkout: bool = False) -> dict[str, Any]:
        job_id = job_id or uuid.uuid4().hex
        job_dir = self.workspace.output_root / "jobs" / job_id
        output_dir = job_dir / "out"
        output_dir.mkdir(parents=True, exist_ok=False)
        log_path = job_dir / "job.log"
        argv = [
            self.workspace.python_executable,
            "-m",
            "appsec_triage_mcp.scanning",
            *(str(output_dir) if arg == "{out}" else arg for arg in arguments),
        ]
        job = Job(job_id, kind, output_dir, log_path, time.time(), project=project or "")
        if repository:
            job.repository = repository
            job.checkout_dir = self.workspace.source_root / ".mcp-checkouts" / job_id
            job.cleanup = "pending"
            job.keep_checkout = keep_checkout
            argv = [sys.executable, "-m", "appsec_triage_mcp.repository_worker",
                    "--url", repository, "--checkout", str(job.checkout_dir), "--output", str(output_dir),
                    *(["--keep-checkout"] if keep_checkout else []), "--", *arguments]
        with self._lock:
            self._jobs[job_id] = job
        try:
            with log_path.open("w+b") as log:
                job.process = self._popen(
                    argv,
                    cwd=self.workspace.runtime_root,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=os.name != "nt",
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
                )
        except OSError as exc:
            job.error = f"Could not start AppSec Triage: {exc}"
            job.finished_at = time.time()
            self._cleanup_checkout(job)
        else:
            waiter = threading.Thread(target=self._wait, args=(job,), name=f"appsec-mcp-{job_id[:8]}", daemon=True)
            job.waiter = waiter
            waiter.start()
        return self.status(job_id)

    def _wait(self, job: Job) -> None:
        returncode = job.process.wait() if job.process is not None else 2
        if job.keep_checkout and returncode == 0 and not job.cancelled:
            job.cleanup = "retained"
        else:
            self._cleanup_checkout(job)
        with self._lock:
            job.returncode = returncode
            job.finished_at = time.time()

    def start_repositories(self, urls: list[str], arguments: list[str], keep_checkout: bool = False) -> list[dict]:
        from .repositories import project_name

        with self._lock:
            active = sum(job.repository != "" and (job.returncode is None or job.cleanup == "retained") and not job.error
                         for job in self._jobs.values())
            if active + len(urls) > 3:
                raise JobError("At most 3 repository jobs may run at once; wait for existing jobs to finish")
            return [self.start(arguments[0], arguments, project=project_name(url), repository=url,
                               keep_checkout=keep_checkout) for url in urls]

    def release_checkout(self, job_id: str) -> dict:
        job = self._get(job_id)
        if job.cleanup == "pending":
            raise JobError("Wait for the repository job to finish before releasing its checkout")
        with self._lock:
            self._cleanup_checkout(job)
        return self.status(job_id)

    def _cleanup_checkout(self, job: Job) -> None:
        if job.checkout_dir is None:
            return
        path = job.checkout_dir
        expected_parent = (self.workspace.source_root / ".mcp-checkouts").resolve()
        try:
            if path.resolve().parent != expected_parent or path.name != job.id or path.is_symlink():
                raise OSError("Checkout path is outside its managed directory")
            if path.exists():
                shutil.rmtree(path)
            job.cleanup = "removed"
        except OSError:
            job.cleanup = "failed"
            job.error = "Could not remove the temporary checkout; inspect its managed workspace"

    def _get(self, job_id: str) -> Job:
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError:
                raise JobError(f"Unknown MCP job: {job_id}") from None

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            ids = sorted(self._jobs, key=lambda item: self._jobs[item].started_at, reverse=True)
        return [self.status(job_id) for job_id in ids]

    def status(self, job_id: str) -> dict[str, Any]:
        job = self._get(job_id)
        with self._lock:
            if job.returncode is None and job.process is not None and not job.error and job.checkout_dir is None:
                returncode = job.process.poll()
                if returncode is not None:
                    job.returncode = returncode
                    job.finished_at = time.time()
            if job.cancelled:
                state = "cancelled"
            elif job.error or job.returncode not in (None, 0):
                state = "failed"
            elif job.returncode == 0:
                state = "succeeded"
            else:
                state = "running"
            ended = job.finished_at or time.time()
            result = {
                "job_id": job.id,
                "kind": job.kind,
                "status": state,
                "exit_code": job.returncode,
                "output_dir": str(job.output_dir),
                "log_file": str(job.log_path),
                "duration_s": round(max(0.0, ended - job.started_at), 1),
            }
            if job.project:
                result["project"] = job.project
            if job.repository:
                result["repository"] = job.repository
                result["checkout_cleanup"] = job.cleanup
                result["source_target"] = f".mcp-checkouts/{job.id}/source"
            if job.error:
                result["error"] = job.error
            if state == "failed" and job.returncode == 1:
                result["note"] = (
                    "Exit 1 can mean a scanner failure or a triggered --fail-on security gate; inspect the log."
                )
            elif state == "failed" and job.returncode == 2:
                result["note"] = (
                    "Exit 2 means configuration, required tools, or run completeness failed; inspect the log."
                )
            return result

    def log(self, job_id: str, offset: int = 0, max_chars: int = 12000) -> dict[str, Any]:
        job = self._get(job_id)
        if offset < 0:
            raise JobError("offset must be zero or greater")
        max_chars = max(1, min(max_chars, 50000))
        try:
            text = job.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise JobError(f"Cannot read job log: {exc}") from exc
        chunk = text[offset : offset + max_chars]
        return {
            "job_id": job.id,
            "offset": offset,
            "next_offset": offset + len(chunk),
            "total_chars": len(text),
            "truncated": offset + len(chunk) < len(text),
            "text": chunk,
        }

    def review_context(self, job_id: str) -> dict:
        job = self._get(job_id)
        if self.status(job_id)["status"] == "running":
            raise JobError("Wait for the scan to finish before requesting its review context")
        path = self.artifact_path(job_id, job.output_dir / "summary-scan.json")
        return json.loads(path.read_text(encoding="utf-8")).get("review_context", {})

    def result(self, job_id: str) -> dict[str, Any]:
        job = self._get(job_id)
        result = self.status(job_id)
        summaries = []
        for path in sorted(job.output_dir.rglob("*summary-*.json")):
            path = self.artifact_path(job_id, path)
            item: dict[str, Any] = {"path": str(path)}
            try:
                item["data"] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                item["error"] = str(exc)
            summaries.append(item)
        result["summaries"] = summaries
        result["reports"] = [str(self.artifact_path(job_id, path))
                             for path in sorted(job.output_dir.glob("report-*.html"))]
        result["verdicts"] = [str(self.artifact_path(job_id, path))
                              for path in sorted(job.output_dir.glob("*verdicts-*.jsonl"))]
        result["findings"] = [str(self.artifact_path(job_id, path))
                              for path in sorted(job.output_dir.glob("findings-*.jsonl"))]
        scan_dir = job.output_dir / "scans"
        if not scan_dir.is_dir() and job.kind == "scan" and not job.repository:
            scan_dir = job.output_dir
        result["scanner_reports"] = (
            [
                str(self.artifact_path(job_id, path))
                for path in sorted(scan_dir.iterdir())
                if path.is_file()
                and path.suffix in (".json", ".sarif")
                and path.name not in {".sbom.json", "scan-manifest.json"}
            ]
            if scan_dir.is_dir()
            else []
        )
        manifest = scan_dir / "scan-manifest.json"
        result["scan_manifest"] = str(self.artifact_path(job_id, manifest)) if manifest.is_file() else None
        return result

    def artifact_path(self, job_id: str, path: Path) -> Path:
        root = self._get(job_id).output_dir.resolve()
        resolved = path.resolve()
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise JobError("Result artifact must be an existing file inside the job output directory")
        return resolved

    def save_result(self, project: str, report_markdown: str, source_job_id: str | None = None) -> dict[str, Any]:
        if not project.strip() or len(project) > 200 or any(ord(c) < 32 for c in project):
            raise JobError("project must contain 1 to 200 printable characters")
        if not report_markdown.strip() or len(report_markdown.encode("utf-8")) > 1024 * 1024:
            raise JobError("report_markdown must contain 1 byte to 1 MiB of text")
        job_id = source_job_id or uuid.uuid4().hex
        if source_job_id:
            if self.status(source_job_id)["status"] == "running":
                raise JobError("Wait for scanners to finish before saving the client review")
            output = self._get(source_job_id).output_dir
        else:
            output = self.workspace.output_root / "jobs" / job_id / "out"
            output.mkdir(parents=True, exist_ok=False)
        log = output.parent / "job.log"
        if not source_job_id:
            log.write_text("Report supplied by the MCP client; no scanner pipeline was run.\n", encoding="utf-8")
        (output / "report-review.md").write_text(report_markdown, encoding="utf-8")
        (output / "report-review.html").write_text(
            '<!doctype html><html lang="ru"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{html.escape(project)} — AppSec review</title>"
            '<style>body{max-width:960px;margin:40px auto;padding:0 24px;font:16px system-ui}'
            'pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'
            f"<h1>{html.escape(project)}</h1><p>Report supplied by the MCP client.</p>"
            f"<pre>{html.escape(report_markdown)}</pre></html>", encoding="utf-8")
        now = time.time()
        if source_job_id:
            self.release_checkout(source_job_id)
        else:
            job = Job(job_id, "review", output, log, now, project=project,
                      finished_at=now, returncode=0)
            with self._lock:
                self._jobs[job_id] = job
        return self.result(job_id)

    def bundle(self, job_id: str) -> Path:
        result = self.result(job_id)
        if result["status"] == "running":
            raise JobError("Wait for the AppSec job to finish before exporting its result")
        job = self._get(job_id)
        paths = [Path(item) for key in ("reports", "verdicts", "findings", "scanner_reports") for item in result[key]]
        paths.extend(Path(item["path"]) for item in result["summaries"])
        if result["scan_manifest"]:
            paths.append(Path(result["scan_manifest"]))
        markdown = job.output_dir / "report-review.md"
        if markdown.exists():
            paths.append(markdown)
        bundle = job.output_dir.parent / f"appsec-result-{job_id}.zip"
        temporary = bundle.with_name(f".{uuid.uuid4().hex}.zip")
        try:
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("result.json", json.dumps(result, ensure_ascii=False, indent=2))
                size = 0
                for path in sorted(set(paths)):
                    resolved = self.artifact_path(job_id, path)
                    size += resolved.stat().st_size
                    if size > 200 * 1024 * 1024:
                        raise JobError("Result bundle exceeds the 200 MiB uncompressed limit")
                    archive.write(resolved, path.relative_to(job.output_dir).as_posix())
            temporary.replace(bundle)
        finally:
            temporary.unlink(missing_ok=True)
        return bundle

    def report_path(self, job_id: str, report: str | None = None) -> Path | None:
        job = self._get(job_id)
        if report is not None:
            if not report or Path(report).name != report or not report.endswith(".html"):
                raise JobError("report must be an HTML file name, not a path")
            path = (job.output_dir / report).resolve()
            if path.parent != job.output_dir.resolve() or not path.is_file():
                raise JobError("Report must be an existing HTML file in the job output directory")
            return self.artifact_path(job_id, path)
        reports = sorted(job.output_dir.glob("report-*.html"))
        if not reports:
            return None
        preferred = job.output_dir / "report-llm-ru.html"
        return self.artifact_path(job_id, preferred if preferred in reports else reports[0])

    def report(self, job_id: str, report: str | None = None, offset: int = 0, max_chars: int = 64000) -> dict:
        if self.status(job_id)["status"] == "running":
            raise JobError("Wait for the AppSec job to finish before reading the HTML report")
        if offset < 0:
            raise JobError("offset must be zero or greater")
        path = self.report_path(job_id, report)
        if path is None:
            raise JobError("This job has no HTML report; inspect its status and log")
        if path.stat().st_size > 50 * 1024 * 1024:
            raise JobError("HTML report exceeds the 50 MiB read limit")
        text = path.read_text(encoding="utf-8")
        chunk = text[offset:offset + max(1, min(max_chars, 64000))]
        return {"job_id": job_id, "report": path.name, "text": chunk,
                "next_offset": offset + len(chunk), "truncated": offset + len(chunk) < len(text)}

    def findings(self, job_id: str, offset: int = 0, limit: int = 20) -> dict:
        if offset < 0 or not 1 <= limit <= 100:
            raise JobError("offset must be nonnegative; limit must be between 1 and 100")
        job = self._get(job_id)
        path = self.artifact_path(job_id, job.output_dir / "findings-scan.jsonl")
        rows = []
        more = False
        with path.open(encoding="utf-8") as stream:
            for index, line in enumerate(stream):
                if index < offset:
                    continue
                if len(rows) == limit:
                    more = True
                    break
                rows.append(json.loads(line))
        return {"job_id": job_id, "findings": rows, "next_offset": offset + len(rows), "truncated": more}

    def cancel(self, job_id: str) -> dict[str, Any]:
        job = self._get(job_id)
        with self._lock:
            if job.process is None or job.process.poll() is not None:
                return self.status(job_id)
            job.cancelled = True
        self._signal(job, force=False)
        threading.Thread(target=self._ensure_stopped, args=(job,), daemon=True).start()
        return self.status(job_id)

    def _ensure_stopped(self, job: Job) -> None:
        if job.process is None:
            return
        try:
            job.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._signal(job, force=True)

    def close(self) -> None:
        for item in self.list():
            if item["status"] == "running":
                self.cancel(item["job_id"])
        deadline = time.monotonic() + 5
        for item in self.list():
            job = self._get(item["job_id"])
            if job.process is None:
                continue
            remaining = max(0.0, deadline - time.monotonic())
            try:
                job.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                self._signal(job, force=True)
                try:
                    job.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    continue
            if job.waiter is not None:
                job.waiter.join(timeout=5)
            if job.cleanup == "retained":
                self._cleanup_checkout(job)

    @staticmethod
    def _inside(value: str, root: Path, label: str) -> Path:
        path = Path(value).expanduser()
        candidate = (root / path).resolve() if not path.is_absolute() else path.resolve()
        if candidate != root and root not in candidate.parents:
            raise JobError(f"The {label} path must stay inside {root}")
        return candidate

    @staticmethod
    def _signal(job: Job, *, force: bool) -> None:
        process = job.process
        if process is None or process.poll() is not None:
            return
        try:
            if os.name == "nt":
                command = ["taskkill", "/PID", str(process.pid), "/T"]
                if force:
                    command.append("/F")
                subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=5,
                )
            else:
                os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
        except (OSError, ProcessLookupError, subprocess.SubprocessError):
            pass
