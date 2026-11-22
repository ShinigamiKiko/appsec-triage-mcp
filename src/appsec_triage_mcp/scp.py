"""Deliver result bundles using OpenSSH scp and operator-configured destinations."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class SCPError(ValueError):
    pass


@dataclass(frozen=True)
class SCPTarget:
    host: str
    user: str
    directory: str
    port: int = 22
    identity_file: str | None = None
    known_hosts_file: str | None = None

    @classmethod
    def from_env(cls, name: str) -> SCPTarget:
        try:
            config = os.environ.get("APPSEC_MCP_SCP_TARGETS_FILE")
            raw = Path(config).read_text(encoding="utf-8") if config else os.environ.get("APPSEC_MCP_SCP_TARGETS_JSON", "{}")
            targets = json.loads(raw)
            if not isinstance(targets, dict) or name not in targets:
                raise SCPError("Unknown SCP target; configure APPSEC_MCP_SCP_TARGETS_JSON")
            target = cls(**targets[name])
        except (OSError, TypeError, ValueError) as exc:
            if isinstance(exc, SCPError):
                raise
            raise SCPError("Invalid SCP targets configuration; set APPSEC_MCP_SCP_TARGETS_FILE or APPSEC_MCP_SCP_TARGETS_JSON") from None
        target.validate()
        return target

    def validate(self):
        if not isinstance(self.host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", self.host):
            raise SCPError("SCP host must be a hostname or IPv4 address")
        if not isinstance(self.user, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", self.user):
            raise SCPError("Invalid SCP username")
        if (not isinstance(self.directory, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]*", self.directory)
                or ".." in PurePosixPath(self.directory).parts):
            raise SCPError("SCP directory must be an absolute POSIX path without spaces or traversal")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise SCPError("SCP port must be between 1 and 65535")
        for path in (self.identity_file, self.known_hosts_file):
            if path is not None and (not isinstance(path, str) or not Path(path).is_absolute()
                                     or not Path(path).is_file() or any(c in path for c in "\r\n\x00")):
                raise SCPError("SCP identity/known_hosts must be existing absolute file paths")

    def send(self, bundle: Path, job_id: str, target_name: str) -> dict:
        self.validate()
        destination = f"{self.user}@{self.host}:{self.directory.rstrip('/')}/{bundle.name}"
        argv = ["scp", "-B", "-P", str(self.port), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15"]
        if self.known_hosts_file:
            argv.extend(["-o", f'UserKnownHostsFile="{self.known_hosts_file}"'])
        try:
            with ExitStack() as stack:
                if self.identity_file:
                    # Windows bind mounts can expose mode 0777. Keep the mounted key read-only,
                    # and use a private 0600 copy in the container's temporary filesystem.
                    directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="appsec-scp-"))
                    private_key = Path(directory) / "identity"
                    private_key.write_bytes(Path(self.identity_file).read_bytes())
                    private_key.chmod(0o600)
                    argv.extend(["-i", str(private_key), "-o", "IdentitiesOnly=yes"])
                argv.extend([str(bundle.resolve()), destination])
                result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            raise SCPError("SCP timed out; delivery is unconfirmed. Check the destination before retrying.") from None
        except OSError:
            raise SCPError("Could not execute scp; install OpenSSH client in the MCP server environment") from None
        if result.returncode:
            # Do not return remote output (which can contain credentials or terminal controls).
            raise SCPError(f"SCP exited with code {result.returncode}; check SSH key, known_hosts and remote directory")
        return {"job_id": job_id, "target": target_name, "destination": destination,
                "bundle": str(bundle), "bytes": bundle.stat().st_size, "sent": True}
