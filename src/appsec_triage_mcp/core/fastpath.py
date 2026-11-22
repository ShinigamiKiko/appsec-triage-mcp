"""Cheap, evidence-backed closures before an LLM is invoked."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import reuse
from .models import (
    EvidenceClass,
    EvidencePackage,
    EvidenceQuote,
    Finding,
    TriageRecord,
    Verdict,
    VerdictLabel,
    VulnerableSymbol,
)


@dataclass(frozen=True)
class FastDecision:
    framework: str
    reason: str
    evidence: tuple[EvidenceQuote, ...]


_RAW_OUTPUT = re.compile(r"\|\s*raw\b|dangerouslySetInnerHTML|v-html|innerHTML|\beval\s*\(", re.I)
_EXTERNAL_INPUT = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)|\$request\b|\breq(?:uest)?\b|getParameter\s*\(|\bparams\b",
    re.I,
)
_LITERAL_INTERNAL_PATH = re.compile(r"['\"](/(?!/|\\)[^'\"]*)['\"]")


def _literal_internal_path(snippet: str) -> bool:
    return bool(_LITERAL_INTERNAL_PATH.search(snippet)) and not re.search(r"\bhttps?://|//", snippet)


def _easyadmin_evidence(roots: list[Path], include_referrer: bool) -> list[EvidenceQuote]:
    for root in roots:
        paths = (
            root / "vendor/easycorp/easyadmin-bundle/src/Router/AdminUrlGenerator.php",
            root / "vendor/easycorp/easyadmin-bundle/src/Admin/AdminUrlGenerator.php",
        )
        path = next((candidate for candidate in paths if candidate.is_file()), None)
        if path is None:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        path_quote = next((line.strip() for line in lines if "UrlGeneratorInterface::ABSOLUTE_PATH" in line), "")
        if not path_quote:
            return []
        quotes = [EvidenceQuote(
            quote=path_quote,
            why="Installed EasyAdmin generates an application-relative path, not an external origin.",
        )]
        if include_referrer:
            query_quote = next((line.strip() for line in lines if "http_build_query" in line), "")
            if not query_quote:
                return []
            quotes.append(EvidenceQuote(
                quote=query_quote,
                why="The copied referrer is encoded as query data rather than a new scheme or host.",
            ))
        return quotes
    return []


def _resolver_quote(pkg: EvidencePackage) -> EvidenceQuote | None:
    if pkg.reachability:
        return EvidenceQuote(quote=pkg.reachability, why="The route index resolved the surrounding endpoint.")
    if pkg.symbol_context:
        return EvidenceQuote(quote=pkg.symbol_context[0], why="The language server resolved a symbol on this path.")
    return None


def _decision(finding: Finding, pkg: EvidencePackage, roots: list[Path]) -> FastDecision | None:
    if finding.dependency is not None or finding.misconfiguration:
        return None
    cwe = (finding.cwe or "").upper()
    if cwe not in {"CWE-79", "CWE-601"}:
        return None
    snippet = (finding.code_context.snippet or pkg.code_context or "").strip()
    if not snippet or _RAW_OUTPUT.search(snippet):
        return None
    lowered = snippet.lower()
    include_referrer = "includereferrer" in lowered
    if _EXTERNAL_INPUT.search(snippet) and not include_referrer:
        return None

    framework = ""
    reason = ""
    contract: list[EvidenceQuote] = []
    if "ea_url" in lowered:
        framework = "symfony-easyadmin"
        reason = "EasyAdmin generates an application-relative URL and HTML-escapes the result."
        contract = _easyadmin_evidence(roots, include_referrer)
    elif "adminurlgenerator" in lowered and "static::class" in lowered and "crud::page_index" in lowered:
        framework = "symfony-easyadmin"
        reason = "The CRUD index URL is generated from the controller class, not request-controlled origin data."
        contract = _easyadmin_evidence(roots, include_referrer=False)
    elif "redirecttoroute" in lowered or re.search(r"\b(?:path|route|reverse)\s*\(", snippet, re.I):
        framework = "framework-router"
        reason = "A named application route is resolved by the framework router, without an external origin."
    elif "uricomponentsbuilder.frompath" in lowered and _literal_internal_path(snippet):
        framework = "spring-mvc"
        reason = "UriComponentsBuilder receives a literal application-relative path."
    elif re.search(r"(?:res\.redirect|ctx?\.redirect)\s*\(", snippet, re.I) and _literal_internal_path(snippet):
        framework = "literal-internal-route"
        reason = "The redirect target is a single-slash application-relative path, not scheme-relative or external."
    elif _literal_internal_path(snippet):
        framework = "literal-internal-route"
        reason = "The generated link is a single-slash application-relative path."
    else:
        return None

    if _RAW_OUTPUT.search(snippet):
        return None
    evidence = [EvidenceQuote(quote=snippet, why="The exact framework call and its arguments were inspected.")]
    evidence.extend(contract)
    if resolver := _resolver_quote(pkg):
        evidence.append(resolver)
    unique = list({quote.quote: quote for quote in evidence}.values())
    if len(unique) < 2:
        return None
    return FastDecision(framework, reason, tuple(unique[:4]))


def evaluate(finding: Finding, pkg: EvidencePackage, roots: list[Path]) -> FastDecision | None:
    """Return a closure only when the exact chain and independent evidence are present."""
    return _decision(finding, pkg, roots)


def record(finding: Finding, decision: FastDecision, *, provider: str) -> TriageRecord:
    verdict = Verdict(
        verdict=VerdictLabel.false_positive,
        evidence_class=EvidenceClass.sanitized_dataflow,
        confidence=0.95,
        evidence_confidence=0.95,
        decision_confidence=0.95,
        confidence_band="high",
        confidence_rationale="Deterministic framework contract plus independent resolver evidence.",
        cwe=finding.cwe,
        vulnerable_symbol=VulnerableSymbol(
            name=(finding.code_context.snippet or "")[:200],
            kind="api_call",
            location=f"{finding.code_context.file_path}:{finding.code_context.start_line or '?'}",
            why=decision.reason,
        ),
        dataflow=[],
        evidence=list(decision.evidence),
        reason=decision.reason,
        missing_information=[],
        requires_human_review=False,
    )
    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        severity=finding.severity,
        rule_id=finding.rule_id,
        kind=finding.kind,
        start_line=finding.code_context.start_line,
        trace=list(finding.trace),
        fingerprint=reuse.fingerprint(finding),
        verdict=verdict,
        decided_by="heuristics",
        provider=provider,
        model=None,
        prompt_id=f"fastpath-{decision.framework}",
        prompt_version="1.0",
        overrides=[f"fastpath:{decision.framework}"],
    )
