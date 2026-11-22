"""A component the platform does not run closes a CVE before anything looks for it."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..prompts import registry
from .verdict import CVEDecision, CVEVerdict

log = logging.getLogger(__name__)


_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["component", "quote", "why"],
    "properties": {
        "component": {"type": "string"},
        "quote": {"type": "string"},
        "why": {"type": "string"},
    },
}

_SKIP_DIRS = {".git", "vendor", "node_modules", "venv", ".venv", "target", "build", "dist", "__pycache__"}
_MARKER_SUFFIXES = {".go", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".java", ".kt", ".php", ".cs",
                    ".yaml", ".yml", ".json", ".toml", ".conf", ".sh"}
_MAX_FILES = 8000
_MAX_BYTES = 600_000
_MAX_MARKERS = 5
_BUILD_TOOL_PACKAGES = {
    "composer/composer", "composer", "npm", "yarn", "pnpm", "pip", "pipenv", "poetry",
    "maven", "gradle", "golang.org/toolchain", "cmd/go", "cmd/cgo", "go/build",
}


def _normalized(text: str) -> str:
    return " ".join((text or "").split())


@dataclass(slots=True)
class Exclusion:
    """The component this CVE needs, the advisory's words for it, and any sign of it in the code."""

    component: object
    quote: str
    why: str = ""
    markers: list[str] = field(default_factory=list)
    deterministic: bool = False

    def render(self) -> str:
        head = (f"вне платформы: {self.component.why} ({self.component.basis}); "
                f"advisory: «{self.quote[:160]}»")
        if not self.markers:
            return head
        return (f"{head}. АНТИПАТТЕРН: в проекте есть признаки компонента, который платформа "
                f"не запускает — {', '.join(self.markers)}")

    def decision(self) -> CVEDecision:
        per_repository = getattr(self.component, "per_repository", False)
        reasons = [f"advisory требует компонент «{self.component.id}»: «{self.quote[:200]}»",
                   f"{self.component.basis}: {self.component.why}",
                   f"владелец: {self.component.owner}",
                   ("закрыто по манифестам этого репозитория, до поиска в коде и до CodeQL" if per_repository
                    else "закрыто по заявленному факту платформы, до поиска в коде и до CodeQL")]
        if self.why:
            reasons.insert(1, self.why)
        if self.markers:
            reasons.append("антипаттерн — компонент всё же найден в проекте: " + ", ".join(self.markers))
        verdict = CVEVerdict.NOT_APPLICABLE if self.deterministic else CVEVerdict.INFRASTRUCTURE
        return CVEDecision(verdict,
                           f"к сервису не относится: {self.component.why}", reasons, list(self.markers))


def candidates(advisory, deployment) -> list:
    """Components in effect whose keyword the advisory mentions."""
    active = getattr(deployment, "components_out_of_scope", None)
    if active is None:
        return []
    text = "\n".join([advisory.summary or "", advisory.details or "", " ".join(advisory.symbols or []),
                      "\n".join(getattr(advisory, "platforms", None) or [])])
    return [
        component for component in active()
        if not component.keywords or any(
            re.search(rf"(?<![\w]){re.escape(keyword)}(?![\w])", text, re.IGNORECASE)
            for keyword in component.keywords)
    ]


def markers_in(roots, markers: list[str]) -> list[str]:
    """`file:line (marker)` for the first marker in each file, bounded."""
    wanted = [m for m in markers if m]
    hits: list[str] = []
    if not wanted:
        return hits
    for root in roots:
        root = Path(root)
        visited = 0
        for parent, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                visited += 1
                if len(hits) >= _MAX_MARKERS or visited > _MAX_FILES:
                    break
                path = Path(parent) / name
                if (path.suffix.lower() not in _MARKER_SUFFIXES
                        and not name.lower().startswith(("dockerfile", "containerfile"))):
                    continue
                try:
                    if path.stat().st_size > _MAX_BYTES:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for marker in wanted:
                    index = text.find(marker)
                    if index >= 0:
                        relative = path.relative_to(root).as_posix()
                        hits.append(f"{relative}:{text.count(chr(10), 0, index) + 1} ({marker})")
                        break
            if len(hits) >= _MAX_MARKERS or visited > _MAX_FILES:
                break
    return hits


def classify(advisory, deployment, client, roots, package: str = "") -> Exclusion | None:
    """The out-of-scope component this CVE needs, or None to analyse it normally."""
    active = (deployment.components_out_of_scope() if deployment is not None else [])
    package_name = (package or getattr(advisory, "package", "") or "").strip().lower()
    if (package_name in _BUILD_TOOL_PACKAGES
            and getattr(deployment, "facts", {}).get("package_managers_build_time_only") is True):
        build_tool = next((item for item in active if item.id == "build_tooling"), None)
        if build_tool is not None:
            return Exclusion(build_tool, f"Package: {package_name}",
                             "пакет является CLI/toolchain и по deployment-контракту запускается только при сборке",
                             deterministic=True)
    if client is None:
        return None
    found = candidates(advisory, deployment)
    if not found:
        return None
    # A component the code shows in use is not out of scope for this service: drop it
    # before asking, so the model is never offered a closure the repository contradicts.
    in_use = {c.id: hits for c in found if getattr(c, "markers_reopen", False)
              and (hits := markers_in(roots, c.markers))}
    for component_id, hits in in_use.items():
        log.info("%s: component %s is in use (%s); analysed normally",
                 advisory.advisory_id, component_id, ", ".join(hits))
    found = [c for c in found if c.id not in in_use]
    if not found:
        return None

    advisory_text = "\n".join(part for part in (advisory.summary, advisory.details) if part)
    symbols = ", ".join(advisory.symbols or [])
    platforms = "\n".join(getattr(advisory, "platforms", None) or [])
    material = "\n".join([
        f"Advisory: {advisory.advisory_id}",
        f"Package: {advisory.package} ({advisory.ecosystem})",
        "=== ADVISORY TEXT ===", advisory_text[:6000] or "(нет текста)",
        *(["=== VULNERABLE SYMBOLS (from the vulnerability database) ===", symbols] if symbols else []),
        *(["=== PLATFORMS THE DATABASE LIMITS EACH VULNERABLE IMPORT TO ===", platforms] if platforms else []),
        "", "=== COMPONENTS THE PLATFORM DOES NOT RUN ===",
        *(f"- {component.id}: {component.describe}" for component in found),
    ])
    try:
        answer = json.loads(client.complete(registry.step("component"), material, json_schema=_SCHEMA).text)
    except Exception as exc:  # noqa: BLE001 - a failed question leaves the finding to the normal chain
        log.warning("component question failed for %s: %s", advisory.advisory_id, exc)
        return None

    chosen = str(answer.get("component") or "").strip()
    component = next((c for c in found if c.id == chosen), None)
    if component is None:
        return None
    quote = str(answer.get("quote") or "").strip()
    if not quote or _normalized(quote) not in _normalized(f"{advisory_text}\n{symbols}\n{platforms}"):
        log.info("discarding ungrounded component answer for %s", advisory.advisory_id)
        return None
    return Exclusion(component, quote, str(answer.get("why") or "").strip()[:300],
                     markers_in(roots, component.markers))
