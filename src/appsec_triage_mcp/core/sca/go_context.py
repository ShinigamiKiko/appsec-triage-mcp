"""Build-aware Go dependency facts for SCA prompts.

The result is deliberately compact. It supplements the SBOM and govulncheck
trace with facts from the module graph and the package set used by the build.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)
_SKIP = {"vendor", "testdata", "node_modules", ".git", "build", "dist"}
_TIMEOUT = int(os.environ.get("APPSEC_GO_CONTEXT_TIMEOUT_S", "120"))


@dataclass(slots=True)
class GoModule:
    root: Path
    path: str
    direct: set[str] = field(default_factory=set)
    loaded: set[str] = field(default_factory=set)
    parents: dict[str, set[str]] = field(default_factory=dict)
    build_ok: bool | None = None
    problem: str = ""

    def facts(self, package: str) -> dict[str, object]:
        module = next((name for name in self.parents if package == name or package.startswith(name + "/")), package)
        return {
            "module": module,
            "direct": module in self.direct,
            "loaded": module in self.loaded,
            "parents": sorted(self.parents.get(module, set())),
            "build_ok": self.build_ok,
            "problem": self.problem,
        }

    def context(self, package: str) -> str:
        package = package or ""
        details = self.facts(package)
        module = str(details["module"])
        direct = bool(details["direct"])
        loaded = bool(details["loaded"])
        parents = list(details["parents"])
        state = "called/imported state comes from govulncheck" if self.build_ok else "build/module state unresolved"
        lines = [
            f"Go dependency context: module={module or package}; "
            f"placement={'direct' if direct else 'transitive'}; "
            f"loaded_by_go_list={'yes' if loaded else 'no/unknown'}",
            f"module graph parents: {', '.join(parents[:4]) or 'unresolved'}",
            f"build profile: {state}",
        ]
        if self.problem:
            lines.append(f"graph disagreement or tool error: {self.problem[:240]}")
        return "\n".join(lines)


def _modules(root: Path) -> list[Path]:
    found = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP and not d.startswith(".")]
        if "go.mod" in files:
            found.append(Path(directory))
    return found


def _direct(path: Path) -> tuple[str, set[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"^\s*module\s+(\S+)", text, re.MULTILINE)
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("module ") or line.startswith("go "):
            continue
        if line.startswith("require "):
            line = line[8:].strip()
        if line.startswith(("(", ")", "replace ", "exclude ")) or "// indirect" in line:
            continue
        parts = line.split()
        if len(parts) >= 2 and "." in parts[0]:
            names.add(parts[0])
    return (match.group(1) if match else ""), names


def _json_stream(text: str):
    decoder, offset = json.JSONDecoder(), 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset >= len(text):
            break
        try:
            value, offset = decoder.raw_decode(text, offset)
        except ValueError:
            break
        yield value


def _run(module: Path, args: list[str]) -> tuple[str, str, int]:
    try:
        proc = subprocess.run(args, cwd=module, capture_output=True, text=True,
                              timeout=_TIMEOUT, encoding="utf-8", errors="replace", check=False)
        return proc.stdout, proc.stderr, proc.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", str(exc), 1


def load(roots: list[Path]) -> list[GoModule]:
    result = []
    for root in roots:
        for module_root in _modules(Path(root)):
            try:
                module_name, direct = _direct(module_root / "go.mod")
            except OSError as exc:
                log.warning("Go module manifest unreadable at %s: %s", module_root, exc)
                continue
            item = GoModule(module_root, module_name, direct)
            graph, graph_err, graph_code = _run(module_root, ["go", "mod", "graph"])
            if graph_code == 0:
                for line in graph.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        item.parents.setdefault(parts[1].rsplit("@", 1)[0], set()).add(parts[0].rsplit("@", 1)[0])
            else:
                item.problem = f"go mod graph: {graph_err.strip() or 'exit ' + str(graph_code)}"
            listing, list_err, list_code = _run(module_root, ["go", "list", "-deps", "-json", "./..."])
            if list_code == 0:
                for package in _json_stream(listing):
                    if isinstance(package, dict):
                        if name := package.get("ImportPath"):
                            item.loaded.add(str(name))
                        mod = package.get("Module") or {}
                        if isinstance(mod, dict) and mod.get("Path"):
                            item.loaded.add(str(mod["Path"]))
                item.build_ok = True
            else:
                item.build_ok = False
                item.problem = "; ".join(x for x in (item.problem, f"go list: {list_err.strip() or 'exit ' + str(list_code)}") if x)
            result.append(item)
    return result
