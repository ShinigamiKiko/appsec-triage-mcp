"""Config loading: one YAML profile per provider + one pipeline config."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from .review_policy import DEFAULT_MANUAL_REVIEW_CWES, normalize_cwe

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")

REPO_ROOT = Path(__file__).resolve().parent / "assets"
CONFIG_DIR = REPO_ROOT / "configs"


class ConfigError(RuntimeError):
    pass


def _expand_env(value: Any) -> Any:
    """Recursively expand ${VAR} and ${VAR:-default} inside loaded YAML."""
    if isinstance(value, str):

        def repl(m: re.Match[str]) -> str:
            var, default = m.group(1), m.group(2)
            got = os.environ.get(var)
            if got is None:
                if default is None:
                    raise ConfigError(f"environment variable {var} is not set (referenced in config)")
                return default
            return got

        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


@dataclass(slots=True)
class ProviderConfig:
    """Transport and decoding settings for the single OpenAI-compatible endpoint."""

    model: str
    base_url: str
    name: str = "llm"
    api_key: str | None = None
    external: bool = True

    @property
    def leaves_the_perimeter(self) -> bool:
        return self.external

    temperature: float | None = 0.0
    max_tokens: int = 32768
    output_token_field: str = "max_tokens"
    top_p: float | None = None
    stop: list[str] = field(default_factory=list)

    json_mode: Literal["none", "json_object", "json_schema"] = "json_object"

    timeout_s: float = 600.0
    connect_timeout_s: float = 10.0
    max_retries: int = 3
    backoff_base_s: float = 1.0
    backoff_max_s: float = 30.0
    concurrency: int = 4

    pricing: dict[str, float] = field(default_factory=dict)
    budget_usd: float | None = None
    keep_raw_response: bool = False
    tool_calling: bool = True

    options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProviderConfig:
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        unknown = set(data) - known
        if unknown:
            raise ConfigError(f"provider: unknown config keys: {sorted(unknown)}")
        if not str(data.get("model") or "").strip() or not str(data.get("base_url") or "").strip():
            raise ConfigError("provider: LLM_MODEL and LLM_BASE_URL must be set")
        return cls(**data)


@dataclass(slots=True)
class HeuristicsConfig:
    enabled: bool = True
    autoclose_on_hard_fp: bool = False
    min_secret_entropy: float = 3.5
    min_secret_length: int = 16
    noisy_path_patterns: list[str] = field(default_factory=list)
    placeholder_markers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PostValidationConfig:
    enabled: bool = True
    require_evidence_quotes: bool = True
    quote_match_threshold: float = 1.0
    escalate_severities: list[str] = field(default_factory=lambda: ["critical", "high"])
    closure_requires_named_defence_above: int = 0


@dataclass(slots=True)
class ScannerConfig:
    """How to invoke one SAST tool."""

    name: str = "scanner"
    mode: Literal["auto", "native", "docker"] = "auto"
    binary: str | list[str] | None = None
    image: str | None = None
    rules: list[str] = field(default_factory=list)
    local_rules_dir: str | None = None
    language: str | None = None
    severity: str | None = None
    timeout_s: float = 1800.0
    per_file_timeout_s: int = 30
    docker_network: bool = False
    docker_args: list[str] = field(default_factory=list)
    run_in_target: bool = False
    suites: dict[str, list[str]] = field(default_factory=dict)
    model_packs: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, name: str) -> ScannerConfig:
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        unknown = set(data) - known - {"name"}
        if unknown:
            raise ConfigError(f"scanner '{name}': unknown config keys: {sorted(unknown)}")
        return cls(**{**data, "name": name})


@dataclass(slots=True)
class ScopeConfig:
    """What is not worth triaging at all."""

    enabled: bool = True
    exclude_rules: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    only_cwes: list[str] = field(default_factory=list)
    min_severity: str | None = None
    only_ecosystems: list[str] = field(default_factory=list)


@dataclass(slots=True)
class LSPConfig:
    """Language servers, for the questions a scanner cannot answer."""

    enabled: bool = False
    reachability: bool = True
    max_definitions: int = 4
    max_callers: int = 8
    startup_timeout_s: float = 120.0
    index_timeout_s: float = 90.0
    request_timeout_s: float = 20.0
    search_timeout_s: float = 60.0
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    required_languages: list[str] = field(default_factory=list)

    def language_for(self, path: str) -> str | None:
        """Which configured server owns this file, by extension."""
        suffix = Path(path).suffix.lower()
        for language, spec in self.servers.items():
            if suffix in [s.lower() for s in (spec or {}).get("extensions", [])]:
                return language
        return None


@dataclass(slots=True)
class VerificationConfig:
    """Second, adversarial pass over selected verdicts."""

    enabled: bool = False
    mode: Literal["advisory", "authoritative"] = "advisory"
    challenge_verdicts: list[str] = field(default_factory=lambda: ["confirmed"])
    challenge_on_override: bool = False
    challenge_cwes: list[str] = field(default_factory=list)
    challenge_closures_above_consequence: int = 0
    challenge_kinds: list[str] = field(default_factory=lambda: ["weakness"])
    downgrade_confirmed: bool = True


@dataclass(slots=True)
class TriageQueueConfig:
    """How much manual review the team is willing to spend, and on what."""

    enabled: bool = True
    review_budget_pct: float = 30.0
    cluster: bool = True
    min_score: int = 50


@dataclass(slots=True)
class PipelineConfig:
    prompt_pack: str = "default"
    max_workers: int = 4
    fail_fast: bool = False
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    queue: TriageQueueConfig = field(default_factory=TriageQueueConfig)
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    lsp: LSPConfig = field(default_factory=LSPConfig)
    heuristics: HeuristicsConfig = field(default_factory=HeuristicsConfig)
    post_validation: PostValidationConfig = field(default_factory=PostValidationConfig)
    code_context_lines: int = 6
    dataflow_context_lines_before: int = 30
    dataflow_context_lines_after: int = 10
    max_code_chars: int = 4000
    max_trace_steps: int = 12
    max_evidence_chars: int = 32000
    context_retrieval_rounds: int = 2
    code_walk_first: bool = True
    # Where things live in the project (routes, access control, ...) from the stack
    # profiles, shown to the code walk as a starting point. Off to measure without it.
    project_map: bool = True
    slow_finding_seconds: int = 900
    max_tool_calls: int = 20
    finding_token_limit: int | None = None
    # Older job configurations use the idor_* names.
    idor_audit: bool = False
    business_logic_audit: bool = False
    business_logic_max_endpoints: int = 200
    business_logic_max_hashes: int = 200
    idor_max_endpoints: int = 200
    idor_include_tests: bool = False
    manual_review_cwes: list[str] = field(default_factory=lambda: list(DEFAULT_MANUAL_REVIEW_CWES))
    callsite_search_rounds: int = 3
    callsite_dataflow_requests: int = 4
    sbom_path: str = ""
    build_untrusted_input: bool = False
    parallel_llm: int = 2
    redact_secrets: bool = False
    secrets_without_model: bool = True
    deployment_config: str | None = None
    resolve_vulnerable_symbols: bool = True
    nvd_api_key: str | None = None
    govulncheck_report: str | None = None
    scan_out_dir: str | None = None

    def __post_init__(self) -> None:
        if self.finding_token_limit is not None and self.finding_token_limit <= 0:
            raise ConfigError("finding_token_limit must be positive")
        configured = {normalize_cwe(item) for item in (self.manual_review_cwes or ())}
        configured.discard("")
        self.manual_review_cwes = list(DEFAULT_MANUAL_REVIEW_CWES) + sorted(
            configured.difference(DEFAULT_MANUAL_REVIEW_CWES))


def load_provider_config(*, config_dir: Path | None = None) -> ProviderConfig:
    """Load the single provider profile."""
    base = config_dir or CONFIG_DIR
    path = base / "providers" / "llm.yaml"
    if not path.is_file():
        raise ConfigError(f"provider profile is missing: {path}")
    data = _expand_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    return ProviderConfig.from_dict(data)


def list_providers(config_dir: Path | None = None) -> list[str]:
    return ["llm"] if ((config_dir or CONFIG_DIR) / "providers" / "llm.yaml").is_file() else []


def _read_pipeline(path: Path, seen: tuple[Path, ...] = ()) -> dict:
    """The file's keys over those of the file it `extends:`, section by section."""
    raw = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.is_file() else {}
    parent = raw.pop("extends", None)
    if not parent:
        return raw
    parent_path = (path.parent / parent).resolve()
    if parent_path in seen or parent_path == path.resolve():
        raise ConfigError(f"{path}: extends loops back to {parent_path}")
    if not parent_path.is_file():
        raise ConfigError(f"{path}: extends a missing file {parent_path}")
    merged = _read_pipeline(parent_path, (*seen, path.resolve()))
    for key, value in raw.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def load_pipeline_config(path: Path | None = None) -> PipelineConfig:
    path = path or (CONFIG_DIR / "pipeline.yaml")
    raw = _expand_env(_read_pipeline(path))
    deployment_config = raw.get("deployment_config")
    if deployment_config:
        deployment_path = Path(str(deployment_config)).expanduser()
        if not deployment_path.is_absolute():
            raw["deployment_config"] = str((path.parent / deployment_path).resolve())
    scope = ScopeConfig(**raw.pop("scope", {}) or {})
    queue = TriageQueueConfig(**raw.pop("queue", {}) or {})
    verify = VerificationConfig(**raw.pop("verification", {}) or {})
    heur = HeuristicsConfig(**raw.pop("heuristics", {}) or {})
    post = PostValidationConfig(**raw.pop("post_validation", {}) or {})
    return PipelineConfig(
        scope=scope, queue=queue, verification=verify, heuristics=heur, post_validation=post, **raw
    )


def load_lsp_config(path: Path | None = None) -> LSPConfig:
    path = path or (CONFIG_DIR / "lsp.yaml")
    if not path.is_file():
        return LSPConfig()
    raw = _expand_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    known = set(LSPConfig.__dataclass_fields__)  # type: ignore[attr-defined]
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(f"{path}: unknown keys {sorted(unknown)}")
    return LSPConfig(**raw)


def load_scanner_config(name: str, *, config_dir: Path | None = None) -> ScannerConfig:
    base = config_dir or CONFIG_DIR
    path = base / "scanners" / f"{name}.yaml"
    if not path.is_file():
        available = sorted(p.stem for p in (base / "scanners").glob("*.yaml"))
        raise ConfigError(f"no scanner profile '{name}' at {path}. Available: {available}")
    data = _expand_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    return ScannerConfig.from_dict(data, name=name)


def list_scanners(config_dir: Path | None = None) -> list[str]:
    base = (config_dir or CONFIG_DIR) / "scanners"
    return sorted(p.stem for p in base.glob("*.yaml")) if base.is_dir() else []
