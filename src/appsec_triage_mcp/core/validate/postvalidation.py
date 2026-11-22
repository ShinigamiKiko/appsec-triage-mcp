"""Post-validation: the model's answer is a proposal, not a decision."""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from ..calibration import DATAFLOW_CLEARABLE_SIGNALS, calibrate
from ..config import PostValidationConfig
from ..consequence import weight as consequence_weight
from ..models import EvidenceClass, EvidencePackage, Finding, Severity, Verdict, VerdictLabel

_WS = re.compile(r"\s+")
_LINE_GUTTER = re.compile(r"^[ \t]*\d+[ \t]*\|[ \t]?", re.MULTILINE)

AUTO_APPLY_CONFIDENCE = 0.86
FP_CLOSURE_CONFIDENCE = 0.90
LOWER_SEVERITY_FP_CONFIDENCE = 0.80

_INPUT_DATAFLOW_CWES = {
    "CWE-22", "CWE-23", "CWE-77", "CWE-78", "CWE-79", "CWE-88", "CWE-89", "CWE-90",
    "CWE-91", "CWE-94", "CWE-95", "CWE-98", "CWE-434", "CWE-502", "CWE-601", "CWE-611",
    "CWE-639", "CWE-643", "CWE-917", "CWE-918", "CWE-943", "CWE-1236",
}


_ARGUES_FALSE_POSITIVE = re.compile(
    r"(not an? (real|genuine|actual) (credential|secret|password|vulnerability|issue)"
    r"|is (clearly )?an? (default )?placeholder"
    r"|not an? (actual|exploitable) (vulnerability|issue|risk)"
    r"|no (real )?security (impact|risk|implication)"
    r"|this is a false.?positive"
    r"|harmless (here|in this context)"
    r"|poses no risk)",
    re.IGNORECASE,
)
_ARGUES_CONFIRMED = re.compile(
    r"(is an? (real|genuine|confirmed|exploitable) (vulnerability|credential|secret)"
    r"|attacker (can|could) (exploit|control|inject)"
    r"|this is exploitable"
    r"|remote code execution is possible)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class ValidationOutcome:
    verdict: Verdict
    overrides: list[str]

    ANNOTATIONS = ("remediation_is_mechanical",)

    @property
    def changed(self) -> bool:
        return any(not o.startswith(self.ANNOTATIONS) for o in self.overrides)


def is_authoritative_govulncheck(finding: Finding) -> bool:
    """Whether govulncheck supplied a usable source-to-sink baseline."""
    if (finding.scanner or "").strip().lower() != "govulncheck":
        return False
    if len(finding.trace) < 2:
        return False
    source = next((step for step in finding.trace if step.role == "source"), None)
    sink = next((step for step in finding.trace if step.role == "sink"), None)
    return (
        source is not None
        and sink is not None
        and bool(source.file_path and source.line is not None)
        and bool(sink.file_path and sink.line is not None)
    )


def govulncheck_baseline(finding: Finding) -> Verdict:
    """Build the scanner-authoritative verdict without asking the model."""
    return Verdict(
        verdict=VerdictLabel.confirmed,
        evidence_class=EvidenceClass.exploitable_dataflow,
        confidence=1.0,
        confidence_band="high",
        confidence_rationale="govulncheck supplied a source-to-sink trace with positioned frames.",
        cwe=finding.cwe,
        reason=(
            "Govulncheck authoritative baseline: a real source-to-sink call trace was supplied. "
            "The trace establishes that the vulnerable symbol is reached."
        ),
        requires_human_review=False,
    )


def check_deployment_mismatch(finding: Finding, pkg: EvidencePackage,
                              advisory_text: str = "", advisory_subject: str = "",
                              deployment=None) -> str | None:
    """Return FP reason for advisory preconditions impossible in this build.

    Only a precondition the build itself rules out closes here: CGO_ENABLED=0 in the
    Dockerfile against an advisory that needs cgo.

    Kernel, SSH, LDAP and incoming TLS are deliberately not closed here by a word in
    the title or the advisory. Words match too much: "syscall" is also the Go
    standard-library package compiled into the binary (GO-2022-0493), "kernel" is
    also semantic-kernel and Jupyter, an Immutable.js DoS names the "kernel OOM-kill"
    among its effects, a PostCSS file read lists "SSH keys" among what it can read.
    Those platform facts are `out_of_scope_components` in configs/deployment.yaml:
    the dependency chain puts them to the model (sca/components.py) and accepts the
    closure only with a verbatim advisory quote tying the flaw to the component.
    `advisory_subject` and `deployment` stay in the signature for the callers.
    """
    del advisory_subject, deployment
    advisory = finding.raw.get("advisory", {})
    details = "\n".join(
        text
        for text in (
            str(advisory.get("details", "")),
            advisory_text,
            finding.title or "",
            finding.description or "",
            finding.dependency.package if finding.dependency else "",
        )
        if text
    )
    if not details:
        return None

    evidence_text = "\n".join(pkg.evidence_blocks + pkg.context_notes)
    if "CGO_ENABLED=0" in evidence_text and re.search(
        r"\bcgo\b.{0,40}\b(?:resolver|build|enabled|compiled)\b",
        details,
        re.IGNORECASE,
    ):
        return (
            "Advisory requires CGO; CGO disabled in build (Dockerfile: CGO_ENABLED=0). "
            "The vulnerability does not apply to this build configuration."
        )

    return None


def apply_govulncheck_gate(
    baseline: Verdict,
    candidate: Verdict | None,
    pkg: EvidencePackage,
    *,
    quote_threshold: float,
    error: str | None = None,
) -> tuple[Verdict, list[str]]:
    """Permit only a grounded, concrete model refutation of the baseline."""
    prefix = "govulncheck authoritative baseline preserved"
    del quote_threshold
    if error:
        return baseline, [f"{prefix}: model error ({error[:240]})"]
    if candidate is None:
        return baseline, [f"{prefix}: model response was unavailable or malformed"]
    if candidate.verdict is not VerdictLabel.false_positive:
        return baseline, [f"{prefix}: model did not explicitly refute the finding"]

    haystack = pkg.quotable_text()
    grounded = bool(candidate.evidence) and all(
        e.quote in haystack and len(e.quote.strip()) >= 4 for e in candidate.evidence
    )
    reason = f"{candidate.reason} {candidate.confidence_rationale}".strip()
    contradiction = len(candidate.reason.strip()) >= 20 and bool(
        re.search(
            r"\b(?:not|outside|patched|fixed|development|dev[- ]only|test|unreachable|"
            r"absent|different|wrong|does not|no vulnerable|not affected|not shipped)\b",
            reason,
            re.IGNORECASE,
        )
    )
    if not grounded or not contradiction:
        return baseline, [
            f"{prefix}: false_positive refutation lacked exact grounded evidence or a concrete contradiction"
        ]
    accepted = candidate.model_copy(
        update={
            "reason": f"{candidate.reason.strip()} [govulncheck baseline refuted by grounded package evidence]",
            "requires_human_review": candidate.requires_human_review,
        }
    )
    return accepted, ["govulncheck authoritative baseline overridden by grounded model refutation"]


def _norm(s: str) -> str:
    return _WS.sub(" ", _LINE_GUTTER.sub("", s)).strip().lower()


def quote_is_grounded(quote: str, haystack: str, threshold: float) -> bool:
    """Exact substring first; fuzzy fallback for whitespace/quote-style drift."""
    q, h = _norm(quote), _norm(haystack)
    if len(q) < 4:
        return False
    if q in h:
        return True
    window = len(q)
    if window > len(h):
        return SequenceMatcher(None, q, h).ratio() >= threshold
    best = 0.0
    step = max(1, window // 4)
    for i in range(0, len(h) - window + 1, step):
        best = max(best, SequenceMatcher(None, q, h[i : i + window]).ratio())
        if best >= threshold:
            return True
    return best >= threshold


def _to_unknown(v: Verdict, evidence_class: EvidenceClass | None = None) -> Verdict:
    return v.model_copy(
        update={
            "verdict": VerdictLabel.unknown,
            "evidence_class": evidence_class or v.evidence_class,
            "requires_human_review": True,
        }
    )


def stated_confidence(result: Verdict) -> float:
    """The confidence the model itself stated; the measured score when it stated none."""
    return (result.self_reported_confidence if result.self_reported_confidence is not None
            else result.confidence)


def _specific_closure_path(result: Verdict, pkg: EvidencePackage) -> bool:
    if pkg.dependency is not None:
        return True
    if result.vulnerable_symbol and result.vulnerable_symbol.name:
        return True
    return any(
        step.grounded and str(getattr(step.role, "value", step.role)) in {"sink", "sanitizer"}
        for step in result.dataflow
    )


def _resolver_verified(pkg: EvidencePackage) -> bool:
    if pkg.symbol_context:
        return True
    if any(fact.startswith(("lsp_find", "lsp_definition", "lsp_references", "lsp_callers"))
           for fact in pkg.code_facts):
        return True
    return bool(pkg.reachability and pkg.repository_code_collected)


def _fp_confidence_threshold(finding: Finding, advisory_cvss_score: float | None) -> float:
    if finding.dependency is not None:
        scores = [score for score in (finding.dependency.cvss_score, advisory_cvss_score) if score is not None]
        if scores and max(scores) < 6.0:
            return LOWER_SEVERITY_FP_CONFIDENCE
    elif finding.kind in ("weakness", "misconfiguration") and finding.severity in (
        Severity.medium, Severity.low, Severity.info,
    ):
        return LOWER_SEVERITY_FP_CONFIDENCE
    return FP_CLOSURE_CONFIDENCE


def _closure_gate_failure(result: Verdict, pkg: EvidencePackage, min_confidence: float) -> str:
    if result.confidence < min_confidence:
        return f"evidence confidence {result.confidence:.2f} is below {min_confidence:.2f}"
    grounded = [quote for quote in result.evidence if quote.grounded]
    if len(grounded) < 2:
        return "fewer than two independent grounded evidence quotes"
    opposing = [signal.name for signal in pkg.heuristic_signals if signal.direction == "toward_confirmed"]
    if opposing:
        return "contradictory deterministic signals: " + ", ".join(opposing)
    if not _specific_closure_path(result, pkg):
        return "no exact sink, route or sanitizer was identified"
    if not _resolver_verified(pkg):
        return "neither LSP nor framework resolver confirmed the path"
    return ""


def apply_confidence_policy(
    result: Verdict, overrides: list[str], pkg: EvidencePackage, *, min_fp_confidence: float = FP_CLOSURE_CONFIDENCE,
) -> Verdict:
    """Apply confirmed and resolver-backed closure verdicts when evidence clears their threshold.

    Unknown and unproven closures stay with a person. The model's own number alone
    is never sufficient for either direction.
    """
    stated = stated_confidence(result)
    if result.verdict is VerdictLabel.unknown:
        if not result.requires_human_review:
            result = result.model_copy(update={"requires_human_review": True})
            overrides.append("confidence_policy: unknown verdict requires human review")
    elif result.verdict is VerdictLabel.false_positive:
        if failure := _closure_gate_failure(result, pkg, min_fp_confidence):
            overrides.append(f"unproven_closure: {failure}")
            result = _to_unknown(result, EvidenceClass.insufficient_context)
            result = result.model_copy(update={"blocking_question": failure})
        elif result.requires_human_review:
            result = result.model_copy(update={"requires_human_review": False})
            overrides.append("closure_policy: resolver-backed evidence clears the automatic-closure gate")
    elif stated > AUTO_APPLY_CONFIDENCE and result.confidence_band == "high":
        if result.requires_human_review:
            result = result.model_copy(update={"requires_human_review": False})
            overrides.append(
                f"confidence_policy: model confidence {stated:.2f} is above the "
                f"{AUTO_APPLY_CONFIDENCE:.2f} auto-apply threshold"
            )
    elif not result.requires_human_review:
        result = result.model_copy(update={"requires_human_review": True})
        overrides.append(
            f"confidence_policy: model confidence {stated:.2f} and measured band "
            f"{result.confidence_band} do not both clear the auto-apply threshold"
        )
    return result


_UNPROVEN_CALL = {"call_unconfirmed", "mentioned"}


_RESOLVED_ROUTES = {"codeql", "callgraph"}
_LSP_CALLED = "LSP нашёл вызовы"


def _project_site(site: str) -> bool:
    """`file:line` in the project's own code — not a dependency, not a status line."""
    head = str(site or "").split()[0] if str(site or "").strip() else ""
    path, _, line = head.rpartition(":")
    if not path or not line.rstrip(",;").isdigit():
        return False
    parts = set(path.replace("\\", "/").split("/"))
    if parts & {"node_modules", "vendor"}:
        return False
    from ..sca import registries

    return registries.go_module_of(path) is None


def _call_resolved(sca) -> bool:
    """Something beyond a name says the project calls the package: an analyser that
    resolves calls, a language server that did, or a call site in project code."""
    if (getattr(sca, "route", "") or "") in _RESOLVED_ROUTES:
        return True
    if any(str(p).startswith(_LSP_CALLED) for p in (getattr(sca, "problems", None) or [])):
        return True
    return any(_project_site(site) for site in (getattr(sca, "call_sites", None) or []))


def _installed_owner(location: str) -> str:
    """The installed package a `path:line` points into, or "" for anything else."""
    head = str(location or "").split()[0] if str(location or "").strip() else ""
    parts = [p for p in head.replace("\\", "/").split("/") if p]
    for index, part in enumerate(parts[:-1]):
        if part in ("node_modules", "vendor"):
            rest = parts[index + 1:]
            two = part == "vendor" or rest[0].startswith("@")
            return "/".join(rest[:2]) if two and len(rest) > 2 else rest[0]
    return ""


def _parent_bridge(result: Verdict, sca):
    """(project step, parent step) of a quoted path into a transitive package, or None."""
    parents = {str(p).strip().lower() for p in (getattr(sca, "loaded_via", None) or []) if str(p).strip()}
    package = (getattr(sca, "package", "") or "").strip()
    if not parents or not package:
        return None
    name = package.rsplit("/", 1)[-1]
    mentions = re.compile(rf"(?<![\w$@/-]){re.escape(name)}(?![\w$-])")
    steps = [s for s in result.dataflow if s.grounded and s.code]
    project = next((s for s in steps if _project_site(s.location)), None)
    bridge = next((s for s in steps if _installed_owner(s.location).lower() in parents
                   and mentions.search(s.code)), None)
    return (project, bridge) if project is not None and bridge is not None else None


def quoted_parent_path(result: Verdict, sca) -> str:
    """The quoted chain that carries a transitive package's path, or "".

    The project never calls a transitive package, so "no call site in project code" is
    its normal state and cannot be what a confirmation lacks. What it needs instead:
    a step in the project's own code and a step in the installed source of a package
    that loads it where that code names the vulnerable package — both quoted
    verbatim from the input, so neither can be invented.
    """
    found = _parent_bridge(result, sca)
    if found is None:
        return ""
    project, bridge = found
    return (f"{project.location} → {bridge.location} "
            f"({_installed_owner(bridge.location)} вызывает {getattr(sca, 'package', '')})")


def cap_unproven_call(result: Verdict, sca, overrides: list[str]) -> Verdict:
    """A confirmation needs a resolved call, not a name that looks like one."""
    if sca is None or result.verdict is not VerdictLabel.confirmed:
        return result
    if quoted_parent_path(result, sca):
        return result
    outcome = getattr(sca, "outcome", "")
    if outcome in _UNPROVEN_CALL:
        overrides.append(
            f"unproven_call: chain outcome {outcome!r} — the call site was matched by name only "
            "and the receiver was never resolved, so it cannot confirm the CVE"
        )
    elif (getattr(sca, "route", "") or "") == "text" and not _call_resolved(sca):
        overrides.append(
            "unproven_call: text route with no call site in project code, no language-server "
            "resolution and no analyser path — nothing shows the project calls this package"
        )
    else:
        return result
    result = _to_unknown(result, EvidenceClass.insufficient_context)
    return result.model_copy(
        update={
            "missing_information": [
                *result.missing_information,
                "a language server or CodeQL must resolve what the matched call belongs to",
            ]
        }
    )


def _missing_input_endpoint(result: Verdict, finding: Finding) -> str:
    if (result.verdict is not VerdictLabel.confirmed or finding.dependency is not None
            or (finding.cwe or "").upper() not in _INPUT_DATAFLOW_CWES
            or result.evidence_class is not EvidenceClass.exploitable_dataflow):
        return ""
    for role in ("source", "sink"):
        model_endpoint = any(
            str(getattr(step.role, "value", step.role)) == role and step.grounded and step.tainted
            and bool(step.code or step.location)
            for step in result.dataflow
        )
        scanner_endpoint = any(
            step.role == role and bool(step.file_path) and step.line is not None
            for step in finding.trace
        )
        if not model_endpoint and not scanner_endpoint:
            return role
    return ""


def validate(
    verdict: Verdict,
    pkg: EvidencePackage,
    finding: Finding,
    cfg: PostValidationConfig,
    *,
    advisory_cvss_score: float | None = None,
) -> ValidationOutcome:
    if not cfg.enabled:
        return ValidationOutcome(verdict, [])

    overrides: list[str] = []
    result = verdict
    haystack = pkg.quotable_text()

    if cfg.require_evidence_quotes:
        checked = [
            e.model_copy(update={"grounded": quote_is_grounded(e.quote, haystack, cfg.quote_match_threshold)})
            for e in result.evidence
        ]
        grounded = [e for e in checked if e.grounded]
        ungrounded = [e for e in checked if not e.grounded]

        if not result.evidence and result.verdict is not VerdictLabel.unknown:
            overrides.append("no_evidence: a decisive verdict was returned without a single quote")
            result = _to_unknown(result)
        elif result.evidence and not grounded:
            overrides.append(
                f"hallucinated_evidence: none of {len(result.evidence)} quotes could be verified "
                f"(first: {ungrounded[0].quote[:80]!r})"
            )
            result = _to_unknown(result, EvidenceClass.insufficient_context)
            result = result.model_copy(
                update={
                    "evidence": checked,
                    "missing_information": [*result.missing_information, "evidence quotes could not be verified"],
                }
            )
        elif ungrounded:
            overrides.append(
                f"unverified_evidence_dropped: {len(ungrounded)} of {len(result.evidence)} entries were "
                f"paraphrase rather than quotation (first: {ungrounded[0].quote[:80]!r}); "
                f"{len(grounded)} verified quote(s) remain"
            )
            result = result.model_copy(update={"evidence": grounded})

        if result.verdict is VerdictLabel.false_positive and grounded:
            search_only = all("search_code" in quote.quote for quote in grounded)
            if search_only and any("INCOMPLETE" in quote.quote for quote in grounded):
                overrides.append("incomplete_search: an incomplete negative search cannot close a finding")
                result = _to_unknown(result, EvidenceClass.insufficient_context)
        if result.verdict is VerdictLabel.confirmed and finding.dependency is None and grounded:
            source_material = "\n".join([
                pkg.code_context or "",
                *pkg.trace,
                *pkg.symbol_context,
                *pkg.evidence_blocks,
                *pkg.code_facts,
            ])
            if not any(quote_is_grounded(quote.quote, source_material, 1.0) for quote in grounded):
                overrides.append("no_source_evidence: confirmation cites only descriptions or derived signals")
                result = _to_unknown(result, EvidenceClass.insufficient_context)

    if result.dataflow:
        checked = []
        ungrounded_steps = 0
        for step in result.dataflow:
            grounded = True
            if step.code:
                grounded = quote_is_grounded(step.code, haystack, cfg.quote_match_threshold)
            elif step.location:
                grounded = quote_is_grounded(step.location, haystack, cfg.quote_match_threshold)
            if not grounded:
                ungrounded_steps += 1
            checked.append(step.model_copy(update={"grounded": grounded}))
        result = result.model_copy(update={"dataflow": checked})

        if ungrounded_steps:
            overrides.append(
                f"unverified_dataflow: {ungrounded_steps} of {len(checked)} step(s) cite code "
                "or locations not present in the input; shown as unverified in the report"
            )
        if (
            result.evidence_class is EvidenceClass.exploitable_dataflow
            and result.verdict is VerdictLabel.confirmed
            and ungrounded_steps == len(checked)
        ):
            overrides.append("unverified_dataflow: every hop was unverifiable, cannot confirm on this basis")
            result = _to_unknown(result, EvidenceClass.insufficient_context)

    if result.vulnerable_symbol and not _symbol_is_grounded(result.vulnerable_symbol.name, pkg, haystack, cfg):
        overrides.append(
            f"unverified_symbol: {result.vulnerable_symbol.name!r} does not appear in the input; dropped"
        )
        result = result.model_copy(update={"vulnerable_symbol": None})

    if result.verdict is VerdictLabel.unknown and not (result.blocking_question or result.missing_information):
        overrides.append("unexplained_unknown: no blocking question and no missing_information supplied")
        result = result.model_copy(
            update={"missing_information": ["model abstained without naming what it lacked"]}
        )

    prose = f"{result.reason} {result.confidence_rationale}"
    if result.verdict is VerdictLabel.confirmed and (m := _ARGUES_FALSE_POSITIVE.search(prose)):
        overrides.append(
            f"contradictory_rationale: verdict is `confirmed` but the explanation argues the opposite "
            f"({m.group(0)!r})"
        )
        result = _to_unknown(result)
    elif result.verdict is VerdictLabel.false_positive and (m := _ARGUES_CONFIRMED.search(prose)):
        overrides.append(
            f"contradictory_rationale: verdict is `false_positive` but the explanation argues the opposite "
            f"({m.group(0)!r})"
        )
        result = _to_unknown(result)

    if result.verdict is VerdictLabel.confirmed and finding.dependency is None and (
            clean := _clean_end(result.dataflow)):
        overrides.append(
            f"contradictory_trace: verdict is `confirmed` but the model's own path marks the {clean} "
            "as not attacker-controlled"
        )
        result = _to_unknown(result)

    if missing_endpoint := _missing_input_endpoint(result, finding):
        overrides.append(f"unproven_dataflow: no grounded attacker-controlled {missing_endpoint} was established")
        result = _to_unknown(result, EvidenceClass.insufficient_context)
        result = result.model_copy(update={
            "missing_information": [*result.missing_information, f"grounded dataflow {missing_endpoint}"],
            "blocking_question": f"Which exact repository line is the attacker-controlled {missing_endpoint}?",
        })

    strong = {s.name for s in pkg.heuristic_signals if s.direction == "toward_confirmed" and s.weight >= 0.7}
    if pkg.lsp_resolved_clean:
        cleared = strong & DATAFLOW_CLEARABLE_SIGNALS
        if cleared:
            strong -= cleared
    if strong and result.verdict is VerdictLabel.false_positive:
        overrides.append(
            f"sanity_conflict: closed as false_positive despite {sorted(strong)}; "
            "a deterministic check found strong evidence the other way"
        )
        secretish = {"known_secret_shape", "high_entropy_literal"} & strong
        result = _to_unknown(result, EvidenceClass.secret_value if secretish else None)
        result = result.model_copy(update={"confidence": min(result.confidence, 0.5)})

    if strong and result.evidence_class is EvidenceClass.test_placeholder:
        overrides.append(f"sanity_conflict: classed as TEST_PLACEHOLDER despite {sorted(strong)}")
        result = result.model_copy(update={"evidence_class": EvidenceClass.secret_value})

    if pkg.code_source == "description_only" and not pkg.repository_code_collected and result.evidence_class in (
        EvidenceClass.exploitable_dataflow,
        EvidenceClass.sanitized_dataflow,
    ):
        overrides.append("sanity_conflict: dataflow verdict claimed without any code context")
        result = _to_unknown(result, EvidenceClass.insufficient_context)

    floor_consequence = cfg.closure_requires_named_defence_above
    if (
        floor_consequence
        and result.verdict is VerdictLabel.false_positive
        and consequence_weight(finding.cwe) >= floor_consequence
    ):
            named = result.evidence_class in (
                EvidenceClass.sanitized_dataflow,
                EvidenceClass.identifier_only,
                EvidenceClass.test_placeholder,
            )
            if not named or not result.evidence:
                overrides.append(
                    f"unexplained_closure: {finding.cwe} is a high-consequence class "
                    f"(weight {consequence_weight(finding.cwe)} >= {floor_consequence}); closing it needs a named, "
                    f"quoted defence, not evidence_class `{result.evidence_class.value}`"
                )
                result = _to_unknown(result, EvidenceClass.insufficient_context)

    if pkg.lsp_required_missing and result.verdict is VerdictLabel.false_positive:
        from ..context.builder import DATAFLOW_CWES

        if (finding.cwe or "").upper() in DATAFLOW_CWES:
            overrides.append(
                "lsp_required_no_answer: closing a dataflow class without symbol resolution is not valid — "
                "the language server is mandatory for this file type and returned nothing"
            )
            result = _to_unknown(result, EvidenceClass.insufficient_context)

    if result.evidence_class is EvidenceClass.insufficient_context:
        if result.verdict is VerdictLabel.false_positive:
            overrides.append(
                "inconsistent_evidence_class: closed as false_positive while declaring INSUFFICIENT_CONTEXT — "
                "a closure needs a named reason (version, shipping, runtime, defence), not missing context")
            result = _to_unknown(result)
        elif result.verdict is VerdictLabel.confirmed and finding.dependency is None:
            overrides.append(
                "inconsistent_evidence_class: confirmed while declaring INSUFFICIENT_CONTEXT — "
                "a code weakness is confirmed on a traced path, not on missing context")
            result = _to_unknown(result)

    cal = calibrate(result, pkg, finding, overrides)
    result = result.model_copy(
        update={
            "self_reported_confidence": result.confidence,
            "model_confidence": result.confidence,
            "evidence_confidence": cal.score,
            "decision_confidence": cal.score,
            "confidence": cal.score,
            "confidence_band": cal.band,
            "confidence_rationale": _merge_rationale(result.confidence_rationale, result.confidence, cal),
        }
    )

    if result.verdict is not VerdictLabel.unknown and result.confidence_band == "low":
        overrides.append(
            f"low_confidence: measured certainty {result.confidence:.2f} (low) for verdict "
            f"'{result.verdict.value}' — {'; '.join(cal.reasons[:2])}"
        )
        result = _to_unknown(result)

    if result.verdict is VerdictLabel.unknown and not result.requires_human_review:
        overrides.append("escalated: unknown always requires human review")
        result = result.model_copy(update={"requires_human_review": True})

    result = apply_confidence_policy(
        result, overrides, pkg, min_fp_confidence=_fp_confidence_threshold(finding, advisory_cvss_score),
    )

    if (
        cfg.escalate_severities
        and finding.severity.value in cfg.escalate_severities
        and not result.requires_human_review
        and result.verdict is VerdictLabel.confirmed
    ):
        overrides.append(
            f"escalated: a confirmed {finding.severity.value}-severity finding always keeps a human in the loop"
        )
        result = result.model_copy(update={"requires_human_review": True})

    dep = pkg.dependency
    if (
        result.verdict is VerdictLabel.confirmed
        and dep is not None
        and dep.upgrade_target
        and result.requires_human_review
        and not (finding.severity.value in ("critical",) and result.evidence_class is EvidenceClass.exploitable_dataflow)
    ):
        result = result.model_copy(update={"requires_human_review": False})
        overrides.append(
            f"remediation_is_mechanical: upgrade {dep.package} to {dep.upgrade_target} — "
            "confirmed, with a published fix on the installed branch, so this is a patch task "
            "rather than a triage decision"
        )

    if finding.cwe and result.cwe != finding.cwe:
        result = result.model_copy(update={"cwe": finding.cwe})

    if result.verdict is VerdictLabel.unknown and not result.blocking_question and overrides:
        result = result.model_copy(update={"blocking_question": _question_from_override(overrides, verdict)})

    return ValidationOutcome(result, overrides)


def _clean_end(dataflow) -> str:
    """"source" or "sink" when the path says the value there is not attacker-controlled.

    A confirmed code finding rests on input reaching the sink. A path whose every source
    is clean, or whose sink receives a clean value, argues the finding away — whatever
    the verdict field says. Measured: `{{ field.formattedValue }}` confirmed while its own
    path called the source "clean" (a URL from the router).
    """
    for role in ("source", "sink"):
        steps = [s for s in dataflow if getattr(s.role, "value", s.role) == role]
        if steps and not any(s.tainted for s in steps):
            return role
    return ""


def _symbol_is_grounded(name: str, pkg: EvidencePackage, haystack: str, cfg: PostValidationConfig) -> bool:
    """Is the named symbol real?"""
    if quote_is_grounded(name, haystack, cfg.quote_match_threshold):
        return True
    dep = pkg.dependency
    if dep is None:
        return False
    lowered = name.lower()
    if dep.package.lower() not in lowered:
        return False
    version = (dep.installed_version or "").lower().lstrip("v")
    return not version or version in lowered or "@" not in lowered


def _merge_rationale(model_text: str, self_reported: float | None, cal) -> str:
    """Keep the model's reasoning, then say what the measured score is built on."""
    measured = "; ".join(cal.reasons) or "no distinguishing evidence either way"
    said = f"model stated {self_reported:.2f}" if self_reported is not None else "model stated no number"
    lines = [t for t in (model_text.strip(),) if t]
    lines.append(f"Measured certainty {cal.score:.2f} ({cal.band}) — {measured}. [{said}]")
    return " ".join(lines)


def _question_from_override(overrides: list[str], original: Verdict) -> str:
    """Turn the triggering check into the question a reviewer should answer."""
    kind = overrides[0].split(":", 1)[0]
    said = original.verdict.value
    templates = {
        "hallucinated_evidence": (
            f"The model concluded `{said}` but not one of its cited lines exists in the input. "
            "Open the file and judge the code directly — there is nothing here to audit."
        ),
        "no_evidence": (
            f"The model concluded `{said}` without citing a single line. "
            "Decide from the code directly — there is nothing to audit here."
        ),
        "sanity_conflict": (
            "A deterministic check contradicts the model's reading. "
            "Confirm by hand whether the flagged value is a real credential or a placeholder."
        ),
        "unverified_dataflow": (
            "The reconstructed path cites code that is not in the analyzer output. "
            "Re-run the scanner with full trace, or trace the value by hand."
        ),
        "contradictory_rationale": (
            "The model's written explanation argues against its own verdict. "
            "Read the reason field and the code, and decide which one is right."
        ),
        "contradictory_trace": (
            "The model confirmed the finding, yet its own path says the value is not attacker-controlled "
            "at the source or the sink. Check where the value comes from: input, or something the "
            "application builds itself (a router URL, a constant, configuration)."
        ),
        "unexplained_closure": (
            "A high-consequence finding was closed without naming what makes it safe. "
            "Find the defence in the code, or treat the finding as real."
        ),
        "low_confidence": (
            f"The model leaned `{said}`, but the measured certainty fell below the floor — the evidence "
            "behind it did not hold up. Treat as undecided and review the code directly."
        ),
        "lsp_required_no_answer": (
            "The language server is mandatory for this file type but resolved nothing, so the origin of "
            "the flagged values is unverified. Fix the server (`appsec-triage doctor`) and re-run, or "
            "trace by hand where the values on the flagged line come from."
        ),
    }
    return templates.get(kind, f"Automated checks overrode a `{said}` verdict ({kind}). Review by hand.")


_BOUND_CALL = {"present", "actual"}


def guard_dependency_verdict(result: Verdict, sca, overrides: list[str]) -> Verdict:
    """The model does not get to overrule the dependency chain on a hunch.

    * a call bound to the package (outcome `present`/`actual`, attributed by import,
      CodeQL or LSP) cannot become `false_positive` unless the model names a defence
      (SANITIZED_DATAFLOW) or a precondition fact (IDENTIFIER_ONLY);
    * the shipping check has the last word on shipping: a model that closes a package
      the running application loads, on the ground that it "does not ship", is wrong.
    """
    if sca is None or result.verdict is not VerdictLabel.false_positive:
        return result
    outcome = getattr(sca, "outcome", "")
    evidence = getattr(sca, "call_evidence", "")
    shipped = getattr(sca, "shipped", "")
    reason = f"{result.reason} {result.confidence_rationale}".lower()
    if shipped == "runtime" and re.search(r"not shipped|не поставляется|dev[- ]?only|devdependencies|"
                                          r"development only|только для разработки", reason):
        overrides.append(
            "shipping_conflict: closed as \"not shipped\", but the shipping check found that the running "
            f"application loads the package ({getattr(sca, 'runtime', '') or 'runtime'})")
        return _to_unknown(result, EvidenceClass.insufficient_context)
    if (outcome in _BOUND_CALL and evidence in ("import", "codeql", "psalm", "lsp")
            and result.evidence_class not in (EvidenceClass.sanitized_dataflow, EvidenceClass.identifier_only)):
        overrides.append(
            f"chain_conflict: the dependency chain found a call bound to the package (outcome {outcome!r}, "
            f"by {evidence}); closing it needs a named defence or precondition, not "
            f"`{result.evidence_class.value}`")
        return _to_unknown(result, EvidenceClass.insufficient_context)
    return result


def cap_unproven_dependency_confirmation(
    result: Verdict, finding: Finding, chain, overrides: list[str], sca=None
) -> Verdict:
    """An affected version alone cannot establish this application's exploit path."""
    if result.verdict is not VerdictLabel.confirmed or finding.dependency is None or chain is None:
        return result
    parent = _parent_bridge(result, sca) if sca is not None else None
    symbol = getattr(chain, "symbol", None)
    condition = getattr(chain, "condition", None)
    condition_state = getattr(getattr(condition, "state", None), "value", "")
    proven = getattr(chain, "dataflow", None) is not None
    expected = getattr(symbol, "function", "") or ""
    matched = (getattr(chain, "matched_symbol", "") or "").rsplit("::", 1)[-1]
    entries = set(getattr(chain, "entry_points", None) or ())
    parent_reaches = parent is not None and any(
        re.search(rf"(?<![\w$]){re.escape(name)}\s*\(", parent[1].code)
        for name in {expected, *entries} if name)
    graph = getattr(chain, "reachability", None)
    graph_called = bool(
        (getattr(finding.dependency, "ecosystem", "") or "").lower() in ("go", "golang")
        and getattr(graph, "reachable", False) and getattr(graph, "trace", None))
    if getattr(symbol, "declared_in_installed", None) is False:
        missing = "уязвимый символ отсутствует в установленной версии; проверьте механизм по её исходникам"
    elif expected and matched != expected and matched not in entries and not parent_reaches and not graph_called:
        missing = "путь ведёт к публичному API, но не доказан переход к уязвимой функции"
    elif condition_state == "external":
        missing = "обязательное условие эксплуатации в окружении не проверено"
    elif not proven and not parent_reaches and not graph_called:
        missing = "путь до уязвимого вызова не доказан"
    else:
        return result
    overrides.append(f"unproven_dependency: {missing}")
    result = _to_unknown(result, EvidenceClass.insufficient_context)
    return result.model_copy(update={
        "missing_information": [*result.missing_information, missing],
        "blocking_question": missing,
    })


def settle_dependency_review(result: Verdict, finding: Finding, sca, overrides: list[str]) -> Verdict:
    """Who has to look at a model-decided dependency verdict.

    A confirmed finding with a fix is a patch task; only a high-priority one on a
    critical/high advisory keeps a person in the loop. A false positive closes
    automatically only after the resolver-backed evidence gate; weaker or
    contradictory evidence becomes `unknown`. `unknown` always needs a person.
    """
    if sca is None:
        return result
    if result.verdict is VerdictLabel.unknown:
        return result if result.requires_human_review else result.model_copy(update={"requires_human_review": True})
    priority = getattr(sca, "priority", "") or "medium"
    severity = finding.severity.value if finding.severity else ""
    wants_person = (result.verdict is VerdictLabel.confirmed and priority in ("critical", "high")
                    and severity in ("critical", "high"))
    has_fix = bool(finding.dependency and finding.dependency.upgrade_target)
    if result.verdict is VerdictLabel.confirmed and not has_fix:
        wants_person = wants_person or priority in ("critical", "high", "medium")
    stated = stated_confidence(result)
    if result.verdict is VerdictLabel.confirmed and (
        stated <= AUTO_APPLY_CONFIDENCE or result.confidence_band != "high"
    ):
        wants_person = True
    proposed_closure = result.verdict is VerdictLabel.false_positive and result.requires_human_review
    wants_person = wants_person or proposed_closure
    if result.requires_human_review != wants_person:
        overrides.append(
            f"dependency_review: {'a person looks at it' if wants_person else 'no person needed'} — "
            f"verdict {result.verdict.value}, priority {priority}, advisory severity {severity or 'unknown'}"
            + ("" if has_fix or result.verdict is not VerdictLabel.confirmed else ", no published fix")
            + (f", model-proposed closure requires review (stated confidence {stated:.2f})"
               if result.verdict is VerdictLabel.false_positive else ""))
        result = result.model_copy(update={"requires_human_review": wants_person})
    return result
