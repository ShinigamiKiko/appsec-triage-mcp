"""Required scanner selection for the current repository's ecosystems."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import probe_all


_CODEQL_ECOSYSTEMS = {
    "go", "golang", "npm", "pypi", "python", "maven", "java", "rubygems", "cargo", "nuget",
}


def scanners_for_target(target: Path) -> list[str]:
    """Return every required scanner; unavailable tools are failed scan results, not silent omissions."""
    del target
    ecosystems = {part.strip().lower() for part in os.environ.get("APPSEC_ECOSYSTEMS", "").split(",") if part.strip()}
    wanted = ["opengrep"]
    if ecosystems & {"composer", "packagist"}:
        wanted.append("psalm")
    if ecosystems & _CODEQL_ECOSYSTEMS:
        wanted.append("codeql")

    probed = probe_all()
    for scanner in wanted:
        availability = probed.get(scanner)
        if availability is None or not availability.usable:
            print(f"  ✗ {scanner:<10} обязателен, но недоступен: {availability or 'нет в реестре'}", file=sys.stderr)
    return wanted
