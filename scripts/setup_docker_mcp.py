"""Build the local image and register its server entry with Docker MCP on Linux."""

import argparse
import json
import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile

import yaml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="appsec-triage")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--telegram-chat-id")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config = root / ".local" / "config"
    config.mkdir(mode=0o700, parents=True, exist_ok=True)
    entry_file = config / "server-linux.json"
    entry = yaml.safe_load((root / "docker/server.yaml").read_text(encoding="utf-8"))
    entry["volumes"].append(f"{config}:/run/appsec-mcp:ro")
    chat_id = args.telegram_chat_id
    if chat_id is None and entry_file.exists():
        previous = json.loads(entry_file.read_text(encoding="utf-8"))
        chat_id = next((e["value"] for e in previous["env"] if e["name"] == "APPSEC_MCP_TELEGRAM_CHAT_ID"), None)
    if chat_id:
        entry["env"].append({"name": "APPSEC_MCP_TELEGRAM_CHAT_ID", "value": chat_id})
        entry["env"].append({"name": "APPSEC_MCP_TELEGRAM_BOT_TOKEN_FILE", "value": "/run/appsec-mcp/telegram.token"})
    profiles = json.loads(subprocess.check_output(["docker", "mcp", "profile", "list", "--format", "json"]))
    if not args.skip_build:
        subprocess.run(["docker", "build", "-t", entry["image"], "."], cwd=root, check=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=config, delete=False) as tmp:
        json.dump(entry, tmp, ensure_ascii=False, indent=2)
    Path(tmp.name).replace(entry_file)
    if any(p["id"] == args.profile for p in profiles or []):
        action = ["server", "add", args.profile]
    else:
        action = ["create", "--id", args.profile, "--name", args.profile]
    subprocess.run(["docker", "mcp", "profile", *action, "--server", f"file://{entry_file}"], check=True)
    print(f"Ready: docker mcp gateway run --profile {args.profile} --long-lived")


if __name__ == "__main__":
    main()
