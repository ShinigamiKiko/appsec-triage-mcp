"""Applicability checks that can be proved from the deployment contract."""

from __future__ import annotations

import re

_ARCH_ALIASES = {"x86_64": "amd64", "x64": "amd64", "aarch64": "arm64", "x86": "386"}
_WINDOWS_ONLY = re.compile(
    r"(?:windows[- ]only|only on windows|exclusive(?:ly)? on windows|windows-specific|"
    r"windows operating system|windows path|drive letter|\\\\|[.]bat\b|[.]cmd\b)",
    re.IGNORECASE,
)

def go_platform_mismatch(advisory, deployment) -> str | None:
    """Return evidence when every OSV platform row excludes this runtime.

    An empty GOOS/GOARCH row means the advisory applies to an unconstrained
    platform. It therefore prevents an automatic closure.
    """
    if advisory is None or (getattr(advisory, "ecosystem", "") or "").lower() not in {"go", "golang"}:
        return None
    if deployment is None or not getattr(deployment, "enabled", False):
        return None
    facts = getattr(deployment, "facts", {}) or {}
    platform = dict(getattr(deployment, "runtime_platform", {}) or {})
    runtime_os = platform.get("os") or ("linux" if facts.get("linux_workloads_only") else "")
    runtime_arch = _ARCH_ALIASES.get(platform.get("arch", ""), platform.get("arch", ""))
    rows = list(getattr(advisory, "platform_constraints", None) or [])
    if not runtime_os or not rows or any(not row.get("goos") and not row.get("goarch") for row in rows):
        return None

    def applies(row: dict) -> bool:
        goos = {str(v).lower() for v in row.get("goos") or []}
        goarch = {_ARCH_ALIASES.get(str(v).lower(), str(v).lower()) for v in row.get("goarch") or []}
        return (not goos or runtime_os in goos) and (not goarch or not runtime_arch or runtime_arch in goarch)

    if any(applies(row) for row in rows):
        return None
    target = runtime_os + (f"/{runtime_arch}" if runtime_arch else "")
    limits = ", ".join(
        f"{row.get('path') or '(package)'}: "
        + "; ".join(part for part in (
            "GOOS=" + ",".join(row.get("goos") or []) if row.get("goos") else "",
            "GOARCH=" + ",".join(row.get("goarch") or []) if row.get("goarch") else "",
        ) if part)
        for row in rows
    )
    return f"OSV ограничивает уязвимые импорты платформами [{limits}], рабочая платформа {target} в них не входит"


def node_platform_mismatch(advisory, deployment) -> str | None:
    """Close only strongly Windows-specific Node advisories on Linux workloads."""
    if advisory is None or (getattr(advisory, "ecosystem", "") or "").lower() not in {
            "npm", "node", "javascript"}:
        return None
    if deployment is None or not getattr(deployment, "enabled", False):
        return None
    facts = getattr(deployment, "facts", {}) or {}
    if not facts.get("linux_workloads_only"):
        return None
    text = "\n".join(str(value or "") for value in
                       (getattr(advisory, "summary", ""), getattr(advisory, "details", "")))
    if not re.search(r"\bwindows\b", text, re.IGNORECASE) or not _WINDOWS_ONLY.search(text):
        return None
    return "advisory явно ограничивает дефект Windows, а deployment-контракт подтверждает Linux-контейнеры"
