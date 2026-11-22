"""Route, authorization and persistence map for business-logic review."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding

_AUTH_CWES = {"CWE-639", "CWE-862", "CWE-863", "CWE-287", "CWE-306"}
_TENANT_HINT = re.compile(r"owner|tenant|user_id|customer_id|account_id", re.I)
_CLASS = re.compile(r"\bclass\s+\w+(?:\s+extends\s+(?P<parent>[\w\\]+))?", re.I)
_GO_FUNC = re.compile(r"\bfunc\s+(?:\([^)]*\)\s+)?(?P<name>[A-Za-z_]\w*)\s*\(")
_GO_ROUTE = re.compile(
    r"(?P<router>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\."
    r"(?P<verb>GET|POST|PUT|PATCH|DELETE|HEAD|Handle|HandleFunc|Any|All)\s*"
    r"\(\s*[\"'](?P<path>[^\"']+)[\"']\s*,\s*"
    r"(?:(?:http\.)?HandlerFunc\s*\(\s*)?(?P<handler>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)",
    re.I,
)
_GO_GROUP_ASSIGN = re.compile(
    r"(?P<group>[A-Za-z_]\w*)\s*(?::=|=)\s*"
    r"(?P<parent>[A-Za-z_]\w*)\.(?:Group|Route)\s*\(\s*[\"'](?P<prefix>[^\"']*)",
    re.I,
)
_GO_USE = re.compile(
    r"(?P<group>[A-Za-z_]\w*)\s*\.Use\s*\((?P<middleware>[^\n)]*)\)", re.I
)
_GO_GROUP = re.compile(
    r"(?P<group>[A-Za-z_]\w*)\s*(?:[:=].*?\b|\.)"
    r"(?:Group|Route)\s*\([^\n]*\)"
    r"|(?P<use>[A-Za-z_]\w*)\s*\.Use\s*\((?P<middleware>[^\n)]*)\)",
    re.I,
)
_GO_AUTH = re.compile(
    r"\b(?:auth|authenticate|authenticated|authorization|authorize|jwt|session|acl|rbac|permission|tenant|"
    r"require|guard|protect|ensure)"
    r"[A-Za-z0-9_]*\b",
    re.I,
)


def _relative_files(root: Path, pattern: str, limit: int = 8) -> list[str]:
    base = root / "src"
    if not base.is_dir():
        return []
    return [path.relative_to(root).as_posix() for path in list(base.rglob(pattern))[:limit]]


def _controller_file(finding: Finding, roots: list[Path]) -> Path | None:
    raw = finding.code_context.file_path.replace("\\", "/")
    for root in roots:
        direct = root / raw
        if direct.is_file():
            return direct
        for candidate in root.rglob(Path(raw).name):
            if candidate.is_file():
                return candidate
    return None


def _go_authorization(finding: Finding, roots: list[Path]) -> list[str]:
    """Collect Go route and middleware facts without claiming enforcement.

    Go routers register handlers from a different file than the handler itself.
    This lexical map gives the model the registration sites and keeps unresolved
    dispatch explicit until gopls or CodeQL proves the edge.
    """
    raw = (finding.code_context.file_path or "").replace("\\", "/")
    if not raw.lower().endswith(".go"):
        return []
    target_name = ""
    target_path = None
    for root in roots:
        candidate = root / raw
        if candidate.is_file():
            target_path = candidate
            break
        matches = list(root.rglob(Path(raw).name))
        if matches:
            target_path = matches[0]
            break
    if target_path is not None:
        try:
            lines = target_path.read_text(encoding="utf-8", errors="replace").splitlines()
            line = max(1, finding.code_context.start_line or 1)
            before = "\n".join(lines[max(0, line - 1):line + 2])
            funcs = list(_GO_FUNC.finditer("\n".join(lines[max(0, line - 20):line + 2])))
            if funcs:
                target_name = funcs[-1].group("name")
            elif match := _GO_FUNC.search(before):
                target_name = match.group("name")
        except OSError:
            pass

    registrations: list[str] = []
    for root in roots:
        for path in root.rglob("*.go"):
            if any(part in {"vendor", "testdata", "node_modules", "dist", "build"} for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            groups: dict[str, tuple[str, list[str]]] = {}
            for number, source_line in enumerate(lines, 1):
                if assignment := _GO_GROUP_ASSIGN.search(source_line):
                    parent_prefix, parent_middleware = groups.get(assignment.group("parent"), ("", []))
                    prefix = "/".join(part.strip("/") for part in (parent_prefix, assignment.group("prefix")) if part)
                    groups[assignment.group("group")] = (f"/{prefix}" if prefix else "", list(parent_middleware))
                if use := _GO_USE.search(source_line):
                    group = use.group("group")
                    prefix, middleware = groups.get(group, ("", []))
                    middleware.extend(_GO_AUTH.findall(use.group("middleware")))
                    groups[group] = (prefix, sorted(set(middleware)))
            for match in _GO_ROUTE.finditer(text):
                handler = match.group("handler")
                if target_name and handler != target_name:
                    continue
                line = text.count("\n", 0, match.start()) + 1
                window = "\n".join(lines[max(0, line - 12):line])
                router = match.group("router").split(".", 1)[0]
                prefix, group_middleware = groups.get(router, ("", []))
                middleware = sorted(set(group_middleware + _GO_AUTH.findall(window)))
                status = "possible auth middleware" if middleware else "middleware unresolved"
                rel = path.relative_to(root).as_posix()
                registrations.append(
                    f"route: {match.group('verb').upper()} {prefix.rstrip('/')}/{match.group('path').lstrip('/')} -> "
                    f"{handler} ({rel}:{line}; {status}: {', '.join(middleware) or 'none found'})"
                )
            if len(registrations) >= 8:
                break
    if not registrations:
        return ["Go route registration: unresolved (handler may be registered through a group, interface, or framework callback)"]
    return registrations


def render(finding: Finding, roots: list[Path], routes, exposure) -> str:
    if (finding.cwe or "").upper() not in _AUTH_CWES:
        return ""
    if (finding.code_context.file_path or "").lower().endswith(".go"):
        lines = ["Authorization map (derived from current Go repository; unresolved means not proved):"]
        indexed = routes.enclosing_all(finding.code_context.file_path,
                                       finding.code_context.start_line or 0) if routes else []
        if indexed:
            lines.extend(f"route: {route.describe()}" for route in indexed[:6])
        else:
            lines.extend(_go_authorization(finding, roots))
        lines.append("ownership/tenant predicate: inspect the handler's service and repository; route middleware does not prove object ownership")
        return "\n".join(lines)
    route = routes.enclosing(finding.code_context.file_path, finding.code_context.start_line or 0) if routes else None
    controller = _controller_file(finding, roots)
    lines = ["Authorization map (derived from current repository; unresolved means not proved):"]
    if route:
        lines.append(f"route: {route.describe()}")
    elif controller:
        lines.append("route: unresolved (the file is known, but no enclosing route was resolved)")
    else:
        lines.append("route: unresolved")

    if exposure is not None:
        access = exposure.assess(finding.code_context.file_path)
        if access:
            for fact in access:
                suffix = f" ({fact['reason']})" if fact.get("reason") else ""
                lines.append(f"access: {fact['access']} — {fact['route']}{suffix}")
        else:
            lines.append("access: unresolved (no matching route/access facts)")
    else:
        lines.append("access: unresolved (no supported access-control reader)")

    if controller:
        try:
            text = controller.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if match := _CLASS.search(text):
            lines.append(f"controller parent: {match.group('parent') or 'none declared'}")
        services = sorted(set(re.findall(r"\b(\w+(?:Service|Manager|Handler|Repository))\b", text)))
        lines.append("service/repository references: " + (", ".join(services[:12]) if services else "unresolved"))
        for root in roots:
            try:
                lines.append("controller: " + controller.relative_to(root).as_posix())
                break
            except ValueError:
                continue
    voters = [item for root in roots for item in _relative_files(root, "*Voter.php")]
    lines.append("voters: " + (", ".join(voters) if voters else "unresolved"))
    repositories = [item for root in roots for item in _relative_files(root, "*Repository.php")]
    lines.append("repositories: " + (", ".join(repositories) if repositories else "unresolved"))
    entities = [item for root in roots for item in _relative_files(root, "Entity/*.php")]
    lines.append("entities: " + (", ".join(entities) if entities else "unresolved"))

    tenant_hits = []
    for root in roots:
        for relative in repositories:
            path = root / relative
            if not path.is_file():
                continue
            try:
                for number, text in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if _TENANT_HINT.search(text):
                        tenant_hits.append(f"{relative}:{number}: {text.strip()[:180]}")
                        if len(tenant_hits) >= 5:
                            break
            except OSError:
                continue
    lines.append("tenant/owner predicate candidates (not a proof of enforcement): "
                 + (" | ".join(tenant_hits) if tenant_hits else "unresolved"))
    return "\n".join(lines)
