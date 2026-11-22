"""Expose bundled CodeTools to an external MCP client, without an LLM loop."""

from __future__ import annotations

import os
import threading
from pathlib import Path

from .jobs import JobError, JobManager


def load_core():
    from .core.lsp import code_tools

    return code_tools


def bounded_tools_class(module):
    """Keep file reads and LSP locations inside the mounted project, including symlinks."""
    class BoundedCodeTools(module.CodeTools):
        def safe(self, path):
            path = Path(path).resolve()
            return path.is_relative_to(self.root) and not module._SECRET_NAMES.match(path.name)

        def resolve(self, file):
            path = super().resolve(file)
            return path if path is not None and self.safe(path) else None

        def _locations(self, reply, language):
            return [(p, n) for p, n in super()._locations(reply, language) if self.safe(p)]

        def _first_file(self, language):
            return next((p for p, _, _, lang in self._code_files() if lang == language), None)

        def _code_files(self):
            return [item for item in super()._code_files() if self.safe(item[0])]

        def _usages_by_psalm(self, name):
            # The cached Psalm index can refer to files outside the mount. Use LSP instead.
            return None

        def _line(self, path, line):
            return super()._line(path, line) if self.safe(path) else ""

        def _column(self, path, line, name):
            return super()._column(path, line, name) if self.safe(path) else -1

        def search(self, pattern):
            # CodeTools.search reads walked files directly rather than through resolve().
            # Apply the same search scope and limits, checking each resolved path first.
            if not pattern.strip() or len(pattern) > 200 or "\n" in pattern:
                raise JobError("Give one literal substring of 1 to 200 characters")
            rows = []
            for parent, dirs, names in os.walk(self.root):
                dirs[:] = sorted(d for d in dirs if d not in module._SKIP and not d.startswith("."))
                for name in sorted(names):
                    path = Path(parent) / name
                    if not self.safe(path) or module.is_test(self.relative(path)):
                        continue
                    if (path.suffix.lower() not in module._SEARCHABLE
                            and name.lower() not in module._SEARCHABLE_NAMES
                            and not name.lower().startswith("dockerfile")):
                        continue
                    path, _ = self._readable(self.relative(path))
                    if path is None:
                        continue
                    try:
                        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                    except OSError:
                        continue
                    hits = [f"- {self.relative(path)}:{n}: {module._clip(line.strip())}"
                            for n, line in enumerate(lines, 1) if pattern in line][:3]
                    rows.extend(hits)
                    if len(rows) >= module._MAX_LISTED:
                        return "\n".join(rows[:module._MAX_LISTED])
            return "\n".join(rows) or "No matches in the project's production code and configuration."

    return BoundedCodeTools


class CodeSessions:
    def __init__(self, jobs: JobManager):
        self.jobs = jobs
        self._sessions = {}
        self._lock = threading.RLock()

    def call(self, method: str, target: str, *args) -> str:
        root = self.jobs.source_path(target)
        with self._lock:
            if root not in self._sessions:
                module = load_core()
                from .core.config import load_lsp_config
                from .core.lsp.service import LSPService

                config_path = os.environ.get("APPSEC_MCP_LSP_CONFIG")
                cfg = load_lsp_config(Path(config_path) if config_path else None)
                lsp = LSPService(cfg, [root])
                self._sessions[root] = bounded_tools_class(module)(lsp, root)
            from .core.redact import redact_secrets

            answer = getattr(self._sessions[root], method)(*args)
            return (redact_secrets(answer)[0] or "")[:24000]

    def close(self):
        with self._lock:
            for tools in self._sessions.values():
                tools.lsp.close()
            self._sessions.clear()
