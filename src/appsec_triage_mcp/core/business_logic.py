"""Static business-logic review candidates.

This module creates explicit review items for checks scanners do not model well.
The items enter the existing evidence and LLM pipeline with a separate record
kind, so the report can keep business logic apart from SAST.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_left
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from .idor import Endpoint, EndpointInventory
from .idor import discover as discover_endpoints
from .models import CodeContext, Finding, TraceStep


@dataclass(slots=True)
class PasswordHasher:
    file_path: str
    line: int
    user_class: str
    environment: str
    algorithm: str
    options: dict[str, str]
    assessment: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class BusinessLogicInventory:
    endpoints: EndpointInventory
    hash_candidates: list[tuple[str, int, str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    password_hashers: list[PasswordHasher] = field(default_factory=list)

    @property
    def files_scanned(self) -> int:
        return self.endpoints.files_scanned


# Consume comments and literals before looking for a call in executable source.
# The generic factory forms require the algorithm name in their first argument.
_STRING = r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`"""
_TRIPLE = """(?:'''[\\s\\S]*?(?:'''|\\Z)|\"\"\"[\\s\\S]*?(?:\"\"\"|\\Z))"""
_C_COMMENTS = r"//[^\n]*|/\*[\s\S]*?(?:\*/|\Z)"
_ALGORITHM = r"(?:MD[245]|SHA[-_]?(?:1|224|256|384|512))"
_FACTORY_ARGS = rf"""\s*\(\s*['"](?P<algorithm>{_ALGORITHM})['"]"""
_DIRECT = rf"(?P<direct>{_ALGORITHM})"
_JS_HASH = rf"(?:\b(?:crypto\.)?createHash{_FACTORY_ARGS}|\bCryptoJS\.{_DIRECT}\s*\()"
_PY_HASH = rf"(?:\bhashlib\.new{_FACTORY_ARGS}|\bhashlib\.{_DIRECT}\s*\()"
_PHP_HASH = (
    rf"(?<![\w>:])(?:hash(?:_file)?{_FACTORY_ARGS}|(?P<direct>md5|sha1)(?:_file)?\s*\("
    rf"""|openssl_digest\s*\(\s*(?:\$[\w]+|{_STRING})\s*,\s*['"](?P<openssl>{_ALGORITHM})['"])"""
)
_GO_HASH = rf"\b{_DIRECT}\.(?:New|Sum(?:224|256|384|512)?)\s*\("
_JAVA_HASH = rf"\bMessageDigest\.getInstance{_FACTORY_ARGS}"
_PASSWORD = re.compile(r"pass(?:word|wd|phrase)|парол", re.IGNORECASE)
_OBSOLETE = {"md2", "md4", "md5", "sha1"}


def _tokens(calls: str, skip: str) -> re.Pattern:
    return re.compile(rf"(?:{skip}|{_STRING})|(?P<call>{calls})", re.IGNORECASE)


_HASH_TOKENS = {
    ".py": _tokens(_PY_HASH, rf"{_TRIPLE}|\#[^\n]*"),
    ".php": _tokens(_PHP_HASH, rf"{_C_COMMENTS}|\#(?!\[)[^\n]*"),
    ".go": _tokens(_GO_HASH, _C_COMMENTS),
    **dict.fromkeys((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"), _tokens(_JS_HASH, _C_COMMENTS)),
    **dict.fromkeys((".java", ".kt"), _tokens(_JAVA_HASH, rf'{_TRIPLE}|{_C_COMMENTS}')),
}


def _hash_calls(path: Path, content: str):
    tokens = _HASH_TOKENS.get(path.suffix.lower())
    if tokens is None:
        return
    newlines = [m.start() for m in re.finditer("\n", content)]
    for match in tokens.finditer(content):
        if not match["call"]:
            continue
        groups = match.groupdict()
        algorithm = (groups.get("algorithm") or groups.get("openssl") or groups["direct"]).lower()
        algorithm = algorithm.replace("-", "").replace("_", "")
        line_index = bisect_left(newlines, match.start())
        start = newlines[line_index - 1] + 1 if line_index else 0
        end = content.find("\n", match.end())
        expression = content[start:end if end >= 0 else len(content)].strip()
        if path.suffix.lower() == ".php" and re.search(r"\bfunction\s+&?\s*$", content[start:match.start()]):
            continue
        credential = bool(_PASSWORD.search(expression))
        if credential or algorithm in _OBSOLETE:
            yield str(path), line_index + 1, match["call"].strip(), "CWE-916" if credential else "CWE-328"


def _mapping(node) -> dict:
    if isinstance(node, yaml.MappingNode):
        return {key.value: value for key, value in node.value if isinstance(key, yaml.ScalarNode)}
    return {}


def _password_hasher_assessment(algorithm: str, options: dict[str, str]) -> str:
    name = algorithm.lower().replace("-", "")
    if name in {"plaintext", "md2", "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"}:
        return "review"
    if name == "bcrypt" and options.get("cost") == "4":
        return "review"
    if name == "pbkdf2" and options.get("iterations") == "1":
        return "review"
    if name in {"auto", "native", "sodium", "bcrypt", "argon2i", "argon2id", "pbkdf2"}:
        return "configured"
    return "unresolved"


def _password_hashers(path: Path, content: str) -> list[PasswordHasher]:
    # Symfony loads config/packages first and config/packages/<env> for that environment.
    directory_env = "all" if path.parent.name == "packages" else path.parent.name
    document = _mapping(yaml.compose(content, Loader=yaml.SafeLoader))
    sections = [(directory_env, document)]
    for key, value in document.items():
        if key.startswith("when@") and (directory_env == "all" or directory_env == key[5:]):
            sections.append((key[5:], _mapping(value)))
    settings = []
    for environment, section in sections:
        security = _mapping(section.get("security"))
        for block in ("encoders", "password_hashers"):
            for user_class, node in _mapping(security.get(block)).items():
                fields = _mapping(node)
                value = fields.get("algorithm") if isinstance(node, yaml.MappingNode) else node
                algorithm = value.value if isinstance(value, yaml.ScalarNode) and value.tag.endswith(":str") else ""
                options = {k: v.value for k, v in fields.items() if k in {
                    "cost", "time_cost", "memory_cost", "iterations"} and isinstance(v, yaml.ScalarNode)}
                assessment = _password_hasher_assessment(algorithm, options)
                if environment not in {"all", "prod"}:
                    assessment = "environment_only"
                settings.append(PasswordHasher(str(path), (value or node).start_mark.line + 1,
                                               user_class, environment, algorithm, options, assessment))
    return settings


def _hasher_scope(setting: PasswordHasher) -> tuple[Path, str]:
    parent = Path(setting.file_path).parent
    packages = parent if parent.name == "packages" else parent.parent
    return packages, setting.user_class


def discover(
    roots: list[Path], *, endpoint_limit: int = 200, hash_limit: int = 200,
    include_tests: bool = False,
) -> BusinessLogicInventory:
    hash_candidates = []
    password_hashers = []
    warnings = []
    omitted = 0

    def add_candidate(candidate):
        nonlocal omitted
        if len(hash_candidates) < hash_limit:
            hash_candidates.append(candidate)
        else:
            omitted += 1

    def read_hashes(path: Path, content: str):
        if path.suffix.lower() in {".yml", ".yaml"}:
            try:
                password_hashers.extend(_password_hashers(path, content))
            except (yaml.YAMLError, RecursionError):
                warnings.append(f"could not parse Symfony package configuration: {path}")
            return
        for candidate in dict.fromkeys(_hash_calls(path, content)):
            add_candidate(candidate)

    endpoints = discover_endpoints(roots, limit=endpoint_limit, include_tests=include_tests, on_source=read_hashes)
    # Explicit production algorithm overrides the common declaration for this application and user class.
    production = {_hasher_scope(s) for s in password_hashers if s.environment == "prod" and s.algorithm}
    for setting in password_hashers:
        if setting.environment == "all" and _hasher_scope(setting) in production:
            setting.assessment = "overridden_in_prod"
        if setting.assessment == "review":
            expression = f"Symfony password hasher {setting.user_class} ({setting.environment}): {setting.algorithm}"
            if setting.options:
                expression += " " + ", ".join(f"{key}={value}" for key, value in setting.options.items())
            add_candidate((setting.file_path, setting.line, expression, "CWE-916"))
    inventory = BusinessLogicInventory(endpoints=endpoints, hash_candidates=hash_candidates,
                                      warnings=endpoints.warnings + warnings, password_hashers=password_hashers)
    if omitted:
        inventory.warnings.append(f"hash candidate limit {hash_limit}: {omitted} additional candidates omitted")
    return inventory


def to_findings(inventory: BusinessLogicInventory) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in inventory.endpoints.endpoints:
        findings.extend((_endpoint_finding(endpoint, "CWE-639"), _endpoint_finding(endpoint, "CWE-862")))
    for file_path, line, expression, cwe in inventory.hash_candidates:
        findings.append(_hash_finding(file_path, line, expression, cwe))
    return findings


def _endpoint_finding(endpoint: Endpoint, cwe: str) -> Finding:
    category = "IDOR/BOLA" if cwe == "CWE-639" else "authorization"
    question = (
        "Trace object references from requests, including nested and batch references, to the "
        "service or repository operation. Establish how this principal may access that object or tenant."
        if cwe == "CWE-639" else
        "Find the configured route or action policy, supported role or permission, and the code that "
        "enforces it before the sensitive operation. Distinguish public actions and role-restricted actions."
    )
    target = f"{endpoint.method} {endpoint.path}"
    context = f"The registered handler is {endpoint.handler}."
    if endpoint.declared_by == "easyadmin_crud":
        target = endpoint.handler
        context = ("This concrete EasyAdmin CRUD controller inherits framework actions. Check dashboard "
                   "registration, enabled actions, inherited permissions and query scoping. Establish "
                   "applicability from the local project before drawing conclusions about an action.")
    digest = hashlib.sha256(f"{endpoint.finding_id}:{cwe}".encode()).hexdigest()[:20]
    return Finding(
        finding_id=f"business-logic:{cwe.lower()}:{digest}",
        scanner="business-logic-audit",
        kind="business_logic",
        rule_id=f"business-logic/{cwe.lower()}",
        cwe=cwe,
        title=f"{category} review for {target}",
        description=f"{context} {question} Review project source and configuration.",
        code_context=CodeContext(
            file_path=endpoint.file_path.replace("\\", "/"),
            start_line=endpoint.line,
            end_line=endpoint.end_line,
            language=Path(endpoint.file_path).suffix.lstrip(".") or None,
        ),
        trace=[TraceStep(
            file_path=endpoint.file_path,
            line=endpoint.line,
            message=f"{target} ({endpoint.declared_by})",
            role="source",
        )],
        raw={"business_logic": {"category": category, "endpoint": endpoint.as_dict()}},
    )


def _hash_finding(file_path: str, line: int, expression: str, cwe: str) -> Finding:
    file_path = file_path.replace("\\", "/")
    digest = hashlib.sha256(f"{file_path}:{line}:{expression}".encode()).hexdigest()[:20]
    return Finding(
        finding_id=f"business-logic:{cwe.lower()}:{digest}",
        scanner="business-logic-audit",
        kind="business_logic",
        rule_id=f"business-logic/{cwe.lower()}",
        cwe=cwe,
        title=f"Weak or unsafe password/hash algorithm at {Path(file_path).name}:{line}",
        description=(
            "Determine whether the hash or password operation protects credentials, tokens, signatures, "
            "or a non-sensitive integrity value. Check algorithm choice, salt, work factor, key handling, "
            "and verification path. A named algorithm alone is insufficient. This is a static review."
        ),
        code_context=CodeContext(
            file_path=file_path,
            start_line=line,
            end_line=line,
            snippet=expression,
            language=Path(file_path).suffix.lstrip(".") or None,
        ),
        trace=[TraceStep(file_path=file_path, line=line, message=expression, role="sink")],
        raw={"business_logic": {"category": "weak_hash", "expression": expression}},
    )

