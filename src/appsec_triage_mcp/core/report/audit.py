"""JSONL audit trail — one line per decision, append-only, replayable."""

from __future__ import annotations

import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from ..models import TriageRecord
    from ..pipeline import TriageRun


def write_jsonl(run: TriageRun, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).isoformat()
    provenance = getattr(run, "provenance", {}) or {}
    with path.open("w", encoding="utf-8") as fh:
        for record in run.records:
            row = record.model_dump(mode="json")
            row["decided_at"] = stamp
            row["prompt_pack"] = run.prompt_pack
            row["run_id"] = provenance.get("run_id", "")
            row["resume_key"] = provenance.get("resume_key", "")
            row["input_sha256"] = provenance.get("input_sha256", "")
            row["source_commit"] = provenance.get("source_commit", "")
            row["host"] = platform.node()
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


_PROVENANCE_KEYS = ("decided_at", "prompt_pack", "host", "run_id", "resume_key", "input_sha256", "source_commit")


def _from_row(row: dict) -> TriageRecord:
    """One audit line back into a record, provenance stripped."""
    from ..models import TriageRecord

    for key in _PROVENANCE_KEYS:
        row.pop(key, None)
    return TriageRecord.model_validate(row)


def read_jsonl(path: Path) -> list[TriageRecord]:
    """Load an audit log back into records."""
    return [
        _from_row(json.loads(line))
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_summary(run: TriageRun, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = run.counts()
    in_scope = run.in_scope
    needs_review = sum(r.verdict.requires_human_review for r in in_scope)
    decided = len(in_scope) - needs_review
    by_cwe: dict[str, dict[str, int]] = {}
    for r in in_scope:
        bucket = by_cwe.setdefault(r.cwe or "unclassified", {"confirmed": 0, "false_positive": 0, "unknown": 0})
        bucket[r.verdict.verdict.value] += 1

    latencies = sorted(r.latency_ms for r in run.records if r.latency_ms)
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "run_id": run.provenance.get("run_id"),
        **(run.coverage.as_dict() if run.coverage is not None else {"coverage_complete": None}),
        "provider": run.provider,
        "model": run.model,
        "prompt_pack": run.prompt_pack,
        "deployment_config": run.deployment_config,
        "deployment_config_sha256": run.deployment_config_sha256,
        "total": len(run.records),
        "triaged_by_model": run.triaged_count,
        "scope_excluded": run.scope_excluded,
        "reuse": run.reuse,
        "reused_verdicts": sum(1 for r in run.records if r.reused),
        "verdicts": counts,
        "by_cwe": by_cwe,
        "overridden_by_post_validation": sum(1 for r in run.records if r.overrides),
        "errors": sum(1 for r in run.records if r.error),
        "requires_human_review": needs_review,
        "auto_closed": run.auto_closed,
        "auto_eligible": run.auto_eligible,
        "auto_decided_eligible": run.auto_decided_eligible,
        "auto_decision_pct": run.auto_decision_pct,
        "outside_auto_eligible": len(in_scope) - run.auto_eligible,
        "false_positive_pending_review": run.false_positive_pending_review,
        "noise_reduction_pct": run.noise_reduction_pct,
        "decided_by": {
            k: sum(1 for r in run.records if r.decided_by == k)
            for k in ("scope", "heuristics", "policy", "llm", "post_validation", "challenged", "error")
        },
        "decided_without_person": decided,
        "decided_without_person_pct": (
            round(100 * decided / len(in_scope), 1) if in_scope else 0.0),
        "dependency_priority": {
            p: sum(1 for r in run.records if r.sca is not None and r.sca.priority == p)
            for p in ("critical", "high", "medium", "low", "none")
        },
        "dependency_shipping": {
            k: sum(1 for r in run.records if r.sca is not None and r.sca.shipped == k)
            for k in ("runtime", "image_only", "build_only", "unknown")
        },
        "stage_seconds": _stage_seconds(run.records),
        "confidence_spread": _confidence_spread(run.records),
        "latency_ms": {
            "p50": latencies[len(latencies) // 2] if latencies else None,
            "p95": latencies[int(len(latencies) * 0.95)] if latencies else None,
            "max": latencies[-1] if latencies else None,
        },
        "total_cost_usd": run.total_cost_usd,
        "verdict_cost_usd": run.verdict_cost_usd,
        "model_calls": run.model_calls,
    }
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_manifest(run: TriageRun, path: Path) -> Path:
    """Write the run inputs that determine deployment-sensitive decisions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(),
        **run.provenance,
        "provider": run.provider,
        "model": run.model,
        "prompt_pack": run.prompt_pack,
        "deployment_config": run.deployment_config,
        "deployment_config_sha256": run.deployment_config_sha256,
        "coverage": run.coverage.as_dict() if run.coverage is not None else None,
        "total_findings": len(run.records),
        "errors": sum(bool(record.error) for record in run.records),
        "model_calls": run.model_calls,
        "total_cost_usd": run.total_cost_usd,
    }
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


class Journal:
    """Append-only record of finished verdicts, written as the run proceeds."""

    def __init__(self, path: Path, prompt_pack: str, provenance: dict | None = None) -> None:
        self.path = Path(path)
        self._prompt_pack = prompt_pack
        self._provenance = provenance or {}
        self._fh = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        return self

    def __exit__(self, *exc) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def append(self, record) -> None:
        if not self._fh:
            return
        row = record.model_dump(mode="json")
        row["decided_at"] = datetime.now(UTC).isoformat()
        row["prompt_pack"] = self._prompt_pack
        row["run_id"] = self._provenance.get("run_id", "")
        row["resume_key"] = self._provenance.get("resume_key", "")
        row["input_sha256"] = self._provenance.get("input_sha256", "")
        row["source_commit"] = self._provenance.get("source_commit", "")
        row["host"] = platform.node()
        self._fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._fh.flush()

    def done(self) -> None:
        """Called once the durable audit log exists; the journal is then noise."""
        self.__exit__()
        self.path.unlink(missing_ok=True)

    @classmethod
    def recover(cls, path: Path, resume_key: str | None = None) -> list:
        """Verdicts from the same interrupted input and configuration only."""
        path = Path(path)
        if not path.is_file():
            return []
        records = []
        mismatched = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if resume_key is not None and row.get("resume_key") != resume_key:
                    mismatched += 1
                    continue
                records.append(_from_row(row))
            except (json.JSONDecodeError, ValueError):
                continue
        if mismatched:
            import logging

            logging.getLogger(__name__).warning(
                "ignored %d journal record(s) from a different input or configuration", mismatched
            )
        return records


def _stage_seconds(records) -> dict[str, dict[str, float]]:
    """Median and total seconds per pipeline stage: where the run's time went."""
    stages: dict[str, list[float]] = {}
    for record in records:
        for stage, seconds in (getattr(record, "timings", None) or {}).items():
            stages.setdefault(stage, []).append(float(seconds))
    out = {}
    for stage, values in stages.items():
        values.sort()
        out[stage] = {"median": values[len(values) // 2], "total": round(sum(values), 1), "n": len(values)}
    return out


def _confidence_spread(records) -> dict[str, float | None]:
    """How much the calibrated confidence varies across model verdicts.

    Near zero means the number says nothing: forty verdicts at exactly 0.80 is a
    constant, not a measurement, and the auto-apply threshold then never moves.
    """
    import statistics

    values = [r.verdict.confidence for r in records if r.decided_by in ("llm", "post_validation", "challenged")]
    if len(values) < 5:
        return {"n": len(values), "stdev": None, "distinct": len(set(values))}
    return {"n": len(values), "stdev": round(statistics.pstdev(values), 3), "distinct": len(set(values))}
