"""MCP stdio server for the existing AppSec Triage CLI."""

from __future__ import annotations

import atexit
import json
from dataclasses import asdict

from mcp.server.mcpserver import MCPServer

from .assets import AssetKind, DeploymentProfile, asset_index, read_asset, review_instructions
from .code import CodeSessions
from .jobs import JobError, JobManager, Workspace
from .repositories import repository_urls
from .scp import SCPTarget
from .telegram import TelegramNotifier

server = MCPServer(
    "appsec-triage",
    title="AppSec MCP Tools",
    description="Git scanning, code/LSP tools, HTML reports and delivery. No internal LLM or API key required.",
    instructions=("For AppSec analysis, call appsec_job_findings after the scan. For each finding, call "
                  "appsec_get_review_instructions with its review_arguments and apply all returned layers. "
                  "Select deployment_profile=bundled only if the operator identified this project's deployment. "
                  "The server never runs its own LLM. Retain checkouts for code investigation, "
                  "then save the client review with source_job_id to release the checkout."),
    version="0.1.0",
)
_manager: JobManager | None = None
_code_sessions: CodeSessions | None = None


@server.tool(description="List bundled AppSec prompt templates or configuration files, including hashes and sizes.")
def appsec_list_assets(kind: AssetKind = "prompts") -> list[dict]:
    return asset_index(kind)


@server.tool(description="Read a bundled prompt or configuration as versioned text, without expanding environment secrets.")
def appsec_read_asset(kind: AssetKind, name: str) -> str:
    return read_asset(kind, name)


@server.tool(description=("Get base rules, applicable supplements, review policy and verdict schema for one finding. "
                          "Pass review_arguments from appsec_job_findings. job_id supplies detected ecosystems and "
                          "frameworks. Choose deployment_profile=bundled only on operator confirmation for this project."))
def appsec_get_review_instructions(cwe: str | None = None, pack: str = "default", kind: str | None = None,
                                   ecosystems: list[str] | None = None, job_id: str | None = None,
                                   stacks: list[str] | None = None, deployment_profile: DeploymentProfile = "generic") -> dict:
    context = _jobs().review_context(job_id) if job_id else {}
    return review_instructions(cwe, pack, kind, ecosystems if ecosystems is not None else context.get("ecosystems"),
                               stacks if stacks is not None else context.get("stacks"), deployment_profile)


@server.prompt(description="AppSec review using the bundled prompts and policies in the connected client's model.")
def appsec_review(cwe: str = "", ecosystems: str = "", kind: str = "", job_id: str = "",
                  stacks: str = "", deployment_profile: DeploymentProfile = "generic", pack: str = "default") -> str:
    def names(value: str) -> list[str] | None:
        return [name.strip() for name in value.split(",") if name.strip()] if value else None

    data = appsec_get_review_instructions(cwe or None, pack, kind or None, names(ecosystems), job_id or None,
                                          names(stacks), deployment_profile)
    return (data["instructions"] + "\n\nReview policy:\n" + json.dumps(data["review_policy"], ensure_ascii=False)
            + "\n\nVerdict schema:\n" + json.dumps(data["verdict_schema"], ensure_ascii=False))


@server.resource("appsec://assets", description="Index of prompt and configuration assets shipped inside this MCP server.")
def appsec_assets() -> str:
    return json.dumps({kind: asset_index(kind) for kind in ("prompts", "configs")}, ensure_ascii=False)


def _jobs() -> JobManager:
    global _manager
    if _manager is None:
        _manager = JobManager(Workspace.from_env())
    return _manager


def _code() -> CodeSessions:
    global _code_sessions
    if _code_sessions is None:
        _code_sessions = CodeSessions(_jobs())
    return _code_sessions


@server.tool(description="Read up to 80 numbered lines from a project file using AppSec CodeTools; secrets are redacted.")
def read_file(path: str, line: int = 1, target: str = ".") -> str:
    if line < 1:
        raise JobError("line must be 1 or greater")
    return _code().call("read", target, path, line)


@server.tool(description="Literal substring search in project production code and configuration; at most 20 matches.")
def search_code(pattern: str, target: str = ".") -> str:
    return _code().call("search", target, pattern)


@server.tool(description="Find declarations by name across project languages using the agent's language servers.")
def lsp_find_symbol(query: str, target: str = ".") -> str:
    return _code().call("find_symbol", target, query)


@server.tool(description="Find resolved usages of a function, method or class using the agent's language servers.")
def lsp_find_usages(name: str, target: str = ".") -> str:
    return _code().call("find_usages", target, name)


@server.tool(description="List declarations in a project file with their line ranges using LSP.")
def lsp_outline(file: str, target: str = ".") -> str:
    return _code().call("outline", target, file)


@server.tool(description="Read a whole function, method or class by its declaration name using LSP.")
def lsp_read_symbol(file: str, name: str, target: str = ".") -> str:
    return _code().call("read_symbol", target, file, name)


@server.tool(description="Resolve the definition of an identifier at a file and 1-based line inside the project.")
def lsp_definition(file: str, line: int, name: str, target: str = ".") -> str:
    if line < 1:
        raise JobError("line must be 1 or greater")
    return _code().call("definition", target, file, line, name)


@server.tool(description="Find references to an identifier at a file and 1-based line using LSP.")
def lsp_references(file: str, line: int, name: str, target: str = ".") -> str:
    if line < 1:
        raise JobError("line must be 1 or greater")
    return _code().call("references", target, file, line, name)


@server.tool(description="Find callers of the function containing a file and 1-based line using LSP.")
def lsp_callers(file: str, line: int, target: str = ".") -> str:
    if line < 1:
        raise JobError("line must be 1 or greater")
    return _code().call("callers", target, file, line)


def _scanner_args(scanners: list[str] | None) -> list[str]:
    args = []
    for name in scanners or []:
        if not name or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for char in name.lower()):
            raise JobError(f"Invalid scanner name: {name!r}")
        args.extend(["-s", name])
    return args


@server.tool(description="List configured AppSec scanners with availability and versions. No LLM provider is used.")
def appsec_list_scanners() -> dict:
    from .core.scanners import probe_all

    return {name: asdict(status) for name, status in probe_all().items()}


@server.tool(
    description="Start scanners against a directory inside APPSEC_MCP_SOURCE_ROOT. Use job status/log/result tools to follow it."
)
def appsec_start_scan(target: str = ".", scanners: list[str] | None = None) -> dict:
    source = _jobs().source_path(target)
    return _jobs().start("scan", ["scan", str(source), "-o", "{out}", *_scanner_args(scanners)], project=source.name)


@server.tool(description=("Clone 1 to 3 remote Git repositories (comma-separated URLs), scan each in an isolated "
                          "background job and delete temporary checkouts when finished. Reports are preserved. "
                          "Uses AppSec scanners directly, without an internal LLM or provider credentials. "
                          "keep_checkout=true retains code for client analysis; release it or save the client review afterward."))
def appsec_start_repository_scan(
    projects: str,
    scanners: list[str] | None = None,
    ecosystems: list[str] | None = None,
    keep_checkout: bool = False,
) -> list[dict]:
    urls = repository_urls(projects)
    args = ["scan", *_scanner_args(scanners)]
    if ecosystems:
        valid = {"npm", "composer", "pypi", "go", "maven", "rubygems", "cargo", "nuget"}
        if any(item not in valid for item in ecosystems):
            raise JobError("Unknown ecosystem")
        args = ["scan", "--mcp-ecosystems", ",".join(ecosystems), *args[1:]]
    return _jobs().start_repositories(urls, args, keep_checkout=keep_checkout)


@server.tool(description="List AppSec Triage jobs known to this MCP server, newest first.")
def appsec_list_jobs() -> list[dict]:
    return _jobs().list()


@server.tool(description="Get the state, exit code, output directory, and log path of an AppSec Triage job.")
def appsec_job_status(job_id: str) -> dict:
    return _jobs().status(job_id)


@server.tool(description="Read a bounded chunk of a job log. Pass next_offset to continue after a truncated response.")
def appsec_job_log(job_id: str, offset: int = 0, max_chars: int = 12000) -> dict:
    return _jobs().log(job_id, offset, max_chars)


@server.tool(description="Get job state plus parsed summary JSON and paths to reports, verdicts, and scanner outputs.")
def appsec_job_result(job_id: str) -> dict:
    return _jobs().result(job_id)


@server.tool(description="Read normalized scanner findings in pages for analysis by the connected MCP client model.")
def appsec_job_findings(job_id: str, offset: int = 0, limit: int = 20) -> dict:
    page = _jobs().findings(job_id, offset, limit)
    for finding in page["findings"]:
        finding["review_arguments"] = {"job_id": job_id, "cwe": finding.get("cwe"),
                                       "kind": "dependency" if finding.get("dependency") else finding.get("kind")}
    return page


@server.tool(description="Delete a completed job's checkout retained with keep_checkout=true after client analysis.")
def appsec_release_checkout(job_id: str) -> dict:
    if _code_sessions is not None:
        _code_sessions.close()
    return _jobs().release_checkout(job_id)


@server.tool(description="Read a completed job's HTML report in bounded pages, for saving it outside the container.")
def appsec_job_report(job_id: str, report: str | None = None, offset: int = 0, max_chars: int = 64000) -> dict:
    return _jobs().report(job_id, report, offset, max_chars)


@server.tool(description=("Save a report authored by the MCP client as Markdown and escaped HTML. Returns job_id for "
                          "Telegram/SCP delivery. With source_job_id, adds the review to that scan and releases its checkout. "
                          "Does not independently validate the report."))
def appsec_save_result(project: str, report_markdown: str, source_job_id: str | None = None) -> dict:
    if source_job_id and _code_sessions is not None:
        _code_sessions.close()
    return _jobs().save_result(project, report_markdown, source_job_id)


@server.tool(description="Send a completed result as a ZIP via scp to a named destination from server configuration.")
def appsec_send_scp_result(job_id: str, target: str = "default") -> dict:
    destination = SCPTarget.from_env(target)
    bundle = _jobs().bundle(job_id)
    return destination.send(bundle, job_id, target)


@server.tool(
    description=(
        "Send a completed job's scanned project name and status to Telegram, optionally attaching its HTML report. "
        "Uses APPSEC_MCP_TELEGRAM_BOT_TOKEN and APPSEC_MCP_TELEGRAM_CHAT_ID; chat_id can override the default chat."
    )
)
def appsec_send_telegram_result(
    job_id: str,
    chat_id: str | None = None,
    send_report: bool = True,
    report: str | None = None,
) -> dict:
    result = _jobs().result(job_id)
    if result["status"] == "running":
        raise JobError("Wait for the AppSec job to finish before sending its result")
    report_path = _jobs().report_path(job_id, report) if send_report else None
    return TelegramNotifier.from_env(chat_id).send_result(result, report_path)


@server.tool(description="Request termination of a running AppSec Triage job and its process group.")
def appsec_cancel_job(job_id: str) -> dict:
    return _jobs().cancel(job_id)


def main() -> int:
    jobs = _jobs()
    atexit.register(jobs.close)
    atexit.register(lambda: _code_sessions.close() if _code_sessions is not None else None)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
