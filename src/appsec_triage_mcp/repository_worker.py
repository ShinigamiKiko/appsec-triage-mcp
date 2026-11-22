"""Isolated clone -> scanner primitives -> HTML -> cleanup worker (no MCP stdout)."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from .repositories import detect_ecosystems, project_name
from .scanning import run_scan


def run_repository(url: str, checkout: Path, output: Path, arguments: list[str], keep_checkout: bool = False) -> int:
    source = checkout / "source"
    if checkout.exists():
        raise ValueError("Checkout directory already exists")
    checkout.mkdir(parents=True)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"}
    try:
        output.mkdir(parents=True, exist_ok=True)
        if Path("/run/appsec-mcp/id_ed25519").is_file():
            private_key = checkout / "identity"
            private_key.write_bytes(Path("/run/appsec-mcp/id_ed25519").read_bytes())
            private_key.chmod(0o600)
            env["GIT_SSH_COMMAND"] = (
                f"ssh -F /dev/null -i {shlex.quote(private_key.as_posix())} -o IdentitiesOnly=yes "
                "-o BatchMode=yes -o StrictHostKeyChecking=yes "
                "-o UserKnownHostsFile=/run/appsec-mcp/known_hosts"
            )
        print("Cloning repository into an isolated temporary checkout", flush=True)
        cloned = subprocess.run(
            ["git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
             "clone", "--depth", "1", "--", url, str(source)], env=env, timeout=300, check=False)
        if cloned.returncode:
            return cloned.returncode
        mode, *options = arguments
        if mode != "scan":
            raise ValueError("Only scanner operations are supported; this MCP server has no internal LLM agent")
        if options[:1] == ["--mcp-ecosystems"]:
            env["APPSEC_ECOSYSTEMS"] = options[1]
            options = options[2:]
        else:
            ecosystems = detect_ecosystems(source)
            if not ecosystems:
                print("Could not infer ecosystems; pass ecosystems explicitly", file=sys.stderr)
                return 2
            env["APPSEC_ECOSYSTEMS"] = ",".join(ecosystems)
        print(f"Ecosystems: {env['APPSEC_ECOSYSTEMS']}", flush=True)
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--scanner", action="append")
        scanners = parser.parse_args(options).scanner
        os.environ["APPSEC_ECOSYSTEMS"] = env["APPSEC_ECOSYSTEMS"]
        print("Starting AppSec scanner tools", flush=True)
        return run_scan(source, output, scanners, project=project_name(url))
    finally:
        (checkout / "identity").unlink(missing_ok=True)
        if not keep_checkout:
            shutil.rmtree(checkout)
            print("Temporary checkout removed; reports preserved", flush=True)
        else:
            print("Checkout retained for MCP client tools; release after review", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keep-checkout", action="store_true")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    try:
        return run_repository(args.url, args.checkout, args.output, arguments, args.keep_checkout)
    except subprocess.TimeoutExpired:
        print("Git clone timed out", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
