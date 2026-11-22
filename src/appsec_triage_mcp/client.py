"""Python batch runner that uses the Docker MCP Gateway, not the agent CLI directly."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from pathlib import Path

from mcp import Client, StdioServerParameters

from .repositories import repository_urls


async def call(client: Client, name: str, arguments: dict):
    response = await client.call_tool(name, arguments, read_timeout_seconds=180)
    if response.is_error:
        raise RuntimeError("\n".join(item.text for item in response.content if item.type == "text"))
    if response.structured_content is not None:
        data = response.structured_content
        return data["result"] if set(data) == {"result"} else data
    values = [json.loads(item.text) for item in response.content if item.type == "text"]
    if values:
        return values if name in {"appsec_start_repository_scan", "appsec_list_jobs"} else values[0]
    raise RuntimeError(f"MCP tool {name} returned no JSON result")


async def download_report(client: Client, job: dict, output: Path) -> Path:
    offset = 0
    destination = output / f"{job['project']}-{job['job_id']}.html"
    temporary = destination.with_suffix(".html.part")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as stream:
            while True:
                page = await call(client, "appsec_job_report", {"job_id": job["job_id"], "offset": offset})
                stream.write(page["text"])
                if not page["truncated"]:
                    break
                if page["next_offset"] <= offset:
                    raise RuntimeError("Report pagination did not advance")
                offset = page["next_offset"]
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


async def run(args) -> int:
    repository_urls(args.projects)
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    command = ["mcp", "gateway", "run", "--profile", args.profile, "--long-lived",
               "--cpus", str(args.cpus), "--memory", args.memory, "--log-calls=false"]
    parameters = StdioServerParameters(command="docker", args=command, env=dict(os.environ))
    async with Client(parameters, mode="legacy", read_timeout_seconds=180) as client:
        tools = {tool.name for tool in (await client.list_tools()).tools}
        required = {"appsec_start_repository_scan", "appsec_job_status", "appsec_job_result", "appsec_job_report"}
        if not required <= tools:
            raise RuntimeError("AppSec tools are missing from the Docker MCP profile; follow the setup in README.md")
        jobs = await call(client, "appsec_start_repository_scan", {
            "projects": args.projects,
            "scanners": args.scanners.split(",") if args.scanners else None,
            "ecosystems": args.ecosystems.split(",") if args.ecosystems else None,
        })
        pending = {job["job_id"]: job for job in jobs}
        for job in jobs:
            print(f"Started {job['project']}: {job['job_id']}", flush=True)
        deadline = time.monotonic() + args.timeout
        failed = False
        try:
            while pending:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Batch timeout reached")
                for job_id in list(pending):
                    state = await call(client, "appsec_job_status", {"job_id": job_id})
                    if state["status"] == "running" or state.get("checkout_cleanup") == "pending":
                        continue
                    result = await call(client, "appsec_job_result", {"job_id": job_id})
                    (output / f"{state['project']}-{job_id}.json").write_text(
                        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                    print(f"{state['project']}: {state['status']}; checkout: {state.get('checkout_cleanup')}", flush=True)
                    if state["status"] != "succeeded" or not result["reports"]:
                        log_path = output / f"{state['project']}-{job_id}.log"
                        offset = 0
                        with log_path.open("w", encoding="utf-8") as log:
                            while True:
                                page = await call(client, "appsec_job_log", {"job_id": job_id, "offset": offset})
                                log.write(page["text"])
                                if not page["truncated"]:
                                    break
                                offset = page["next_offset"]
                        print(f"Log: {log_path}", flush=True)
                    if result["reports"]:
                        report = await download_report(client, state, output)
                        print(f"HTML: {report}", flush=True)
                    else:
                        failed = True
                        print("No HTML report; details are in the saved job log.", flush=True)
                    failed |= state["status"] != "succeeded"
                    for tool, enabled, options in [
                        ("appsec_send_telegram_result", args.telegram, {"send_report": bool(result["reports"])}),
                        ("appsec_send_scp_result", bool(args.scp), {"target": args.scp}),
                    ]:
                        if enabled:
                            try:
                                await call(client, tool, {"job_id": job_id, **options})
                                print(f"Delivered: {tool}", flush=True)
                            except Exception as exc:  # noqa: BLE001 - keep other reports and deliveries after a failed channel
                                failed = True
                                print(f"Delivery failed: {exc}", flush=True)
                    del pending[job_id]
                if pending:
                    await asyncio.sleep(3)
        finally:
            for job_id in pending:
                await call(client, "appsec_cancel_job", {"job_id": job_id})
        return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Clone, scan and clean up 1 to 3 Git projects via Docker MCP")
    parser.add_argument("projects", nargs="?", help="1 to 3 Git URLs separated by commas")
    parser.add_argument("--profile", default="appsec-triage")
    parser.add_argument("--output", type=Path, default=Path(".local/reports"))
    parser.add_argument("--scanners", help="Comma-separated scanner names; default: AppSec scanner selection")
    parser.add_argument("--ecosystems", help="Comma-separated ecosystems; default: infer for each repository")
    parser.add_argument("--telegram", action="store_true")
    parser.add_argument("--scp", metavar="TARGET", help="SCP destination alias from server configuration")
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--cpus", type=int, default=3)
    parser.add_argument("--memory", default="8Gb")
    args = parser.parse_args()
    if args.projects is None:
        args.projects = input("Git URLs (1 to 3, comma-separated): ").strip()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - command-line boundary reports transport ExceptionGroups too
        def explain(error):
            if isinstance(error, BaseExceptionGroup):
                return "; ".join(explain(child) for child in error.exceptions)
            return f"{type(error).__name__}: {error}"
        print(f"Error: {explain(exc)}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
