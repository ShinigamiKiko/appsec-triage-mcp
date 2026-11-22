"""Validation of remote repository requests shared by MCP and the Python client."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from .jobs import JobError


def repository_urls(projects: str) -> list[str]:
    urls = [value.strip() for value in projects.split(",")]
    if not 1 <= len(urls) <= 3 or any(not value for value in urls):
        raise JobError("Provide 1 to 3 Git repository URLs separated by commas")
    for url in urls:
        if any(c.isspace() or ord(c) < 32 for c in url) or len(url) > 2048:
            raise JobError("Invalid Git URL")
        if re.fullmatch(r"git@[A-Za-z0-9][A-Za-z0-9.-]*:[A-Za-z0-9_./-]+", url):
            continue
        try:
            parsed = urlsplit(url)
            valid = (parsed.scheme in {"https", "ssh"} and parsed.hostname and parsed.path not in {"", "/"}
                     and not parsed.password and not parsed.query and not parsed.fragment
                     and (parsed.scheme != "https" or parsed.username is None))
            _ = parsed.port
        except ValueError:
            valid = False
        if not valid:
            raise JobError("Use HTTPS or SSH Git URLs without passwords, tokens, query parameters or fragments")
    return urls


def project_name(url: str) -> str:
    name = url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    name = name.removesuffix(".git")
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:120] or "project"


def detect_ecosystems(source: Path) -> list[str]:
    manifests = {"package.json": "npm", "composer.json": "composer", "go.mod": "go",
                 "pyproject.toml": "pypi", "requirements.txt": "pypi", "setup.py": "pypi",
                 "pom.xml": "maven", "build.gradle": "maven", "Gemfile": "rubygems", "Cargo.toml": "cargo"}
    suffixes = {".php": "composer", ".go": "go", ".py": "pypi", ".js": "npm", ".ts": "npm",
                ".jsx": "npm", ".tsx": "npm", ".java": "maven", ".rb": "rubygems", ".rs": "cargo",
                ".csproj": "nuget", ".cs": "nuget"}
    found = set()
    for _, dirs, names in os.walk(source):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "vendor", ".venv", "dist", "build"}]
        for name in names:
            ecosystem = manifests.get(name) or suffixes.get(Path(name).suffix.lower())
            if ecosystem:
                found.add(ecosystem)
    return sorted(found)
