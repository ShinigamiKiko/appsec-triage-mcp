"""Shared runtime helpers for CLI commands."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from .. import coverage as coverage_report
from .. import ingest
from .. import review_policy
from .. import reuse as reuse_mod
from .. import scope as scope_filter
from ..config import load_lsp_config, load_pipeline_config, load_provider_config
from ..context.source import SourceResolver
from ..llm.base import LLMAuthError, LLMError
from ..llm.factory import build_client
from ..lsp.service import LSPService, present_languages as lsp_present_languages
from ..lsp.service import required_languages as lsp_required_languages
from ..models import TriageRecord
from ..pipeline import TriagePipeline, TriageRun, _error_record
from ..report import audit, html

_PROGRESS_STATE: dict[str, float] = {}
_PROVEN_OUTCOMES = {"actual", "present"}
_BUSINESS_CWES = {"CWE-639", "CWE-862", "CWE-863", "CWE-328", "CWE-916"}


def progress(done: int, total: int) -> None:
    now = time.monotonic()
    started = _PROGRESS_STATE.setdefault("started", now)
    filled = int(28 * done / total) if total else 28
    print(f"\r  [{'█' * filled}{'·' * (28 - filled)}] {done}/{total}", end="", file=sys.stderr, flush=True)
    elapsed = now - started
    if done == total or now - _PROGRESS_STATE.get("last_line", 0.0) >= 60:
        _PROGRESS_STATE["last_line"] = now
        eta = (elapsed / done) * (total - done) if done else 0.0
        tail = " · finished" if done == total else f" · ~{eta / 60:.0f} min left"
        print(f"\n  {done}/{total} done · {elapsed / 60:.0f} min elapsed{tail}", file=sys.stderr, flush=True)


def preflight_provider(provider_cfg) -> str | None:
    """One tiny call before anything expensive: None when the provider answers.

    A rejected key used to surface 38 minutes into a run — after CodeQL, the
    SBOM, 890 advisory lookups and the SCA preparation — as a stream of
    warnings the run then ignored.
    """
    client = build_client(provider_cfg)
    try:
        client.ping()
    except LLMAuthError as exc:
        return str(exc)
    except LLMError as exc:
        return f"провайдер {provider_cfg.name} не отвечает: {exc}"
    finally:
        client.close()
    return None


def node_modules_problem(roots: list[Path]) -> str | None:
    """A JS project without an installed tree: the language server and the
    package-source lookups are blind, and the run should say so up front."""
    from ..sca.install import projects

    for root in roots:
        # Every project in the tree, not only the root: a frontend in `frontend/` without
        # node_modules leaves CodeQL's type-based framework models (Angular, Vue) blind too.
        for project in projects(Path(root), "package.json"):
            modules = project / "node_modules"
            try:
                empty = not modules.is_dir() or not any(modules.iterdir())
            except OSError:
                empty = True
            if empty:
                return (f"{project}: package.json есть, а node_modules пуст или отсутствует — "
                        "typescript-language-server не построит индекс, исходники пакетов недоступны, "
                        "а модели фреймворков в CodeQL не увидят типы. "
                        "Выполните `yarn install --ignore-scripts` (или `npm ci --ignore-scripts`) до прогона "
                        "или запустите `run --install-deps`; без этого ответы по JS/TS будут неполными.")
    return None


def attach_file_log(out: Path) -> Path:
    """Step-by-step log in the output directory at INFO, whatever the console level.

    The console stays quiet; the file keeps `finding … started / decided in Ns`
    and the per-stage timings, which is what a slow run is diagnosed from.
    """
    import logging

    out.mkdir(parents=True, exist_ok=True)
    path = out / "appsec-triage.log"
    root = logging.getLogger()
    if not any(getattr(h, "baseFilename", None) == str(path.resolve()) for h in root.handlers):
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%H:%M:%S"))
        root.addHandler(handler)
        for existing in root.handlers:
            if existing is not handler and existing.level == logging.NOTSET:
                existing.setLevel(root.level)
        if root.level > logging.INFO or root.level == logging.NOTSET:
            root.setLevel(logging.INFO)
    return path


def gate_count(fail_on: str, counts: dict[str, int], pending_fp: int = 0) -> int | None:
    if fail_on == "none":
        return None
    return {"confirmed": counts["confirmed"], "review": counts["confirmed"] + counts["unknown"] + pending_fp}[fail_on]


def quality_problems(run: TriageRun, business: TriageRun | None = None, *, require_manifest: bool = False,
                     dependency_chain_required: bool = False, tool_calling_failed: bool = False) -> list[str]:
    """Failures that make a report incomplete independently of its security verdicts."""
    problems: list[str] = []
    errors = sum(bool(record.error) for record in run.records)
    if errors:
        problems.append(f"model/triage errors: {errors}")
    if tool_calling_failed:
        problems.append("the configured endpoint rejected function/tool calling required for full repository evidence")
    if business is not None and (business_errors := sum(bool(record.error) for record in business.records)):
        problems.append(f"business-logic errors: {business_errors}")
    coverage = run.coverage
    if coverage is None:
        if require_manifest:
            problems.append("scanner coverage manifest is unavailable")
    else:
        if require_manifest and not coverage.manifest_found:
            problems.append("scanner coverage manifest is unavailable")
        if require_manifest and not coverage.ran:
            problems.append("no scanner completed")
        problems.extend(coverage.gaps())
    if dependency_chain_required:
        dependencies = [record for record in run.records if record.kind == "dependency"]
        if dependencies and not any(record.sca is not None for record in dependencies):
            problems.append("the dependency verification chain did not produce evidence for any dependency")
        tool_failures = sum(
            any(any(marker in issue.lower() for marker in (
                "не выполнен", "недоступ", "не отработал", "не проверен", "не удалось", "упал", "код 255",
            )) for issue in ((record.sca.problems if record.sca else []) or []))
            for record in dependencies
        )
        if tool_failures:
            problems.append(f"dependency analysis tools reported incomplete evidence for {tool_failures} finding(s)")
    if any(key.startswith("ecosystem:") for key in run.scope_excluded):
        problems.append("one or more detected dependency ecosystems were outside triage scope")
    if lsp_gated := sum(
        any(override.startswith("lsp_required_no_answer") for override in record.overrides)
        for record in run.records
    ):
        problems.append(f"mandatory language-server evidence missing for {lsp_gated} finding(s)")
    return problems


def _write_reports(out: Path, run: TriageRun, business: TriageRun | None, warnings: Sequence[str],
                   password_hashers: list[dict]) -> Path:
    title = f"AppSec-триаж — {run.provider}"
    report = html.write(run, out / f"report-{run.provider}.html", title=title,
                        business_logic=business, business_warnings=warnings, password_hashers=password_hashers)
    html.write(run, out / f"report-{run.provider}-ru.html", title=title, russian=True,
               business_logic=business, business_warnings=warnings, password_hashers=password_hashers)
    return report


def run_triage(args: argparse.Namespace, findings_path: Path, out: Path, source_roots: list[Path]) -> int:
    manifest_root = None
    if original := getattr(args, "dependency_manifest_root", None):
        manifest_root = Path(original).expanduser().resolve()
        if not source_roots or not manifest_root.is_dir():
            print("error: --dependency-manifest-root requires a source root and an existing checkout",
                  file=sys.stderr)
            return 2
    if source_roots:
        from ..context.detection import DetectionError, get_source_suffixes
        try:
            get_source_suffixes(source_roots, include_configs=True)
        except DetectionError as exc:
            print(f"error: invalid APPSEC_ECOSYSTEMS: {exc}", file=sys.stderr)
            return 2

    os.environ.setdefault("APPSEC_CACHE_DIR", str(Path(out) / ".appsec-cache"))

    config_path = args.config
    cfg = load_pipeline_config(config_path)
    if not cfg.scope.only_ecosystems:
        cfg.scope.only_ecosystems = sorted(
            part.strip().lower() for part in os.environ.get("APPSEC_ECOSYSTEMS", "").split(",") if part.strip()
        )
    business_logic_cli = getattr(args, "business_logic_audit", None)
    legacy_idor = (business_logic_cli is None and not cfg.business_logic_audit and
                   (cfg.idor_audit or getattr(args, "idor_audit", False)))
    if business_logic_cli is None:
        business_logic_cli = getattr(args, "idor_audit", None)
    business_logic_audit = (cfg.business_logic_audit or cfg.idor_audit) if business_logic_cli is None else business_logic_cli
    business_logic_inventory = None
    business_run = None
    business_error = None
    if deployment_config := getattr(args, "deployment_config", None):
        cfg.deployment_config = str(Path(deployment_config).expanduser().resolve())
    if getattr(args, "prompt_pack", None): cfg.prompt_pack = args.prompt_pack
    if getattr(args, "workers", None): cfg.max_workers = args.workers
    if (parallel := getattr(args, "parallel_llm", None)) is not None:
        if parallel < 1:
            print("error: --parallel-llm must be 1 or more", file=sys.stderr)
            return 2
        cfg.parallel_llm = parallel
    if (resolve := getattr(args, "resolve_symbols", None)) is not None:
        cfg.resolve_vulnerable_symbols = resolve
    if getattr(args, "govulncheck", None): cfg.govulncheck_report = str(args.govulncheck)
    elif getattr(args, "govulncheck_reach", None): cfg.govulncheck_report = str(args.govulncheck_reach)
    if getattr(args, "scan_dir", None): cfg.scan_out_dir = str(args.scan_dir)
    if getattr(args, "sbom", None): cfg.sbom_path = str(args.sbom)
    elif getattr(args, "scan_dir", None) and (Path(args.scan_dir) / ".sbom.json").is_file():
        cfg.sbom_path = str(Path(args.scan_dir) / ".sbom.json")
    if os.environ.get("NVD_API_KEY"): cfg.nvd_api_key = os.environ["NVD_API_KEY"]

    provider_cfg = load_provider_config()
    if provider_cfg.leaves_the_perimeter: cfg.redact_secrets = True
    from .. import provenance as provenance_mod

    run_provenance = provenance_mod.create(
        findings_path=findings_path,
        source_roots=source_roots,
        pipeline_path=config_path,
        lsp_path=getattr(args, "lsp_config", None),
        deployment_path=cfg.deployment_config,
        provider=provider_cfg,
        prompt_pack=cfg.prompt_pack,
        dependency_manifest_root=manifest_root,
    )
    log_path = attach_file_log(out)
    print(f"→ подробный лог: {log_path}", file=sys.stderr)
    if not getattr(args, "no_preflight", False) and not getattr(args, "_preflight_done", False):
        if problem := preflight_provider(provider_cfg):
            print(f"error: {problem}", file=sys.stderr)
            return 2
    findings = ingest.load(findings_path)
    from ..ingest.dependency import qualify_composer_names, qualify_npm_names
    manifest_roots = [manifest_root, *source_roots[1:]] if manifest_root is not None else source_roots
    if qualified := qualify_composer_names(findings, manifest_roots):
        print(f"→ {qualified} Composer package name(s) completed from composer.lock", file=sys.stderr)
    if cfg.sbom_path:
        from ..sca import sbom as sbom_mod
        document, problem = sbom_mod.load(cfg.sbom_path)
        if problem:
            print(f"  ! {problem}", file=sys.stderr)
        elif scoped := qualify_npm_names(findings, document):
            print(f"→ {scoped} npm-имён восстановлены со scope по SBOM", file=sys.stderr)
    if govuln_path := getattr(args, "govulncheck", None):
        from ..ingest import govulncheck as govulncheck_ingest
        try:
            gov_findings = list(govulncheck_ingest.parse(govuln_path))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"error: govulncheck report is unreadable: {exc}", file=sys.stderr)
            return 2
        findings.extend(gov_findings)
        print(f"→ govulncheck: {len(gov_findings)} authoritative traced finding(s)", file=sys.stderr)
    business_findings = [
        f.model_copy(update={"kind": "business_logic"}) for f in findings
        if f.dependency is None and not f.misconfiguration and f.cwe in _BUSINESS_CWES
    ]
    business_ids = {f.finding_id for f in business_findings}
    findings = [f for f in findings if f.finding_id not in business_ids]
    if getattr(args, "limit", None): findings = findings[:args.limit]
    if business_logic_audit:
        if not source_roots:
            print("error: --business-logic-audit requires --source-root", file=sys.stderr)
            return 2
        endpoint_limit = getattr(args, "idor_limit", None)
        if endpoint_limit is None:
            endpoint_limit = cfg.idor_max_endpoints if legacy_idor else cfg.business_logic_max_endpoints
        if min(endpoint_limit, cfg.business_logic_max_hashes) < 1:
            print("error: business logic limits must be positive", file=sys.stderr)
            return 2
        from .. import business_logic as business_logic_mod

        business_logic_inventory = business_logic_mod.discover(
            source_roots,
            endpoint_limit=endpoint_limit,
            hash_limit=cfg.business_logic_max_hashes,
            include_tests=cfg.idor_include_tests,
        )
        generated = business_logic_mod.to_findings(business_logic_inventory)
        business_findings.extend(f for f in generated if not legacy_idor or f.cwe == "CWE-639")
        print(
            f"→ Business Logic audit: discovered {len(business_logic_inventory.endpoints.endpoints)} route/controller declaration(s), "
            f"{len(business_logic_inventory.hash_candidates)} hash candidate(s) "
            f"across {business_logic_inventory.files_scanned} source file(s)",
            file=sys.stderr,
        )
        for warning in business_logic_inventory.warnings:
            print(f"  ! Business Logic discovery: {warning}", file=sys.stderr)
    print(f"→ {len(findings)} finding(s) · provider {provider_cfg.name} ({provider_cfg.model})", file=sys.stderr)
    if cfg.manual_review_cwes:
        print("→ обязательный LLM; human review для confirmed/unknown: " + ", ".join(cfg.manual_review_cwes), file=sys.stderr)
    if cfg.redact_secrets:
        print("→ hosted provider: high-entropy literals are replaced by a description of their shape before the prompt leaves this machine", file=sys.stderr)

    source = SourceResolver(source_roots) if source_roots else None
    if source: print(f"→ widening code context from {source.stats()['roots']} source root(s)", file=sys.stderr)
    symbols = None
    lsp_cfg = load_lsp_config(getattr(args, "lsp_config", None))
    cfg.lsp = lsp_cfg
    if lsp_cfg.enabled and source_roots and not getattr(args, "no_lsp", False):
        if not getattr(args, "_preflight_done", False) and (problem := node_modules_problem(source_roots)):
            print(f"  ! {problem}", file=sys.stderr)
        symbols = LSPService(lsp_cfg, source_roots)
        print("→ language servers enabled (definitions and reachability)", file=sys.stderr)
    required_present = lsp_required_languages(findings + business_findings, lsp_cfg, cfg.scope.only_ecosystems)
    if required_present:
        langs = ", ".join(required_present)
        if symbols is None:
            if getattr(args, "no_lsp", False):
                print(f"  ! {langs} findings present with --no-lsp: dataflow closures for them will be downgraded to unknown — the verdicts are conservative, not complete", file=sys.stderr)
            else:
                reason = "no --source-root given" if not source_roots else "lsp.yaml has enabled: false"
                print(f"error: findings in {langs} present, and the language server is mandatory for them ({reason}).\n       Pass --source-root <repo> with LSP enabled, or accept degraded triage explicitly with --no-lsp.", file=sys.stderr)
                return 2
    if symbols is not None:
        # Every server the findings or the project's own code need, started now: the log
        # shows which ones are alive.
        wanted = set(lsp_present_languages(findings + business_findings, lsp_cfg, cfg.scope.only_ecosystems))
        for lang in sorted(wanted | set(symbols.project_languages())):
            err = symbols.ensure_ready(lang)
            server = ((lsp_cfg.servers.get(lang) or {}).get("command") or ["?"])[0]
            print(f"  {'✗' if err else '✓'} lsp {lang:<10} {err or f'жив ({server})'}", file=sys.stderr)
            if err and lang in required_present:
                print(f"error: the {lang} language server is mandatory but not usable: {err}\n       Fix it (see `appsec-triage doctor`), or accept degraded triage explicitly with --no-lsp.", file=sys.stderr)
                symbols.close()
                return 2

    out.mkdir(parents=True, exist_ok=True)
    journal_path = out / f"verdicts-{provider_cfg.name}.jsonl.partial"
    business_path = out / f"business-logic-verdicts-{provider_cfg.name}.jsonl"
    idor_path = out / f"idor-verdicts-{provider_cfg.name}.jsonl"
    wanted = {f.finding_id for f in findings}
    finding_by_id = {f.finding_id: f for f in findings}
    resume_key = str(run_provenance.get("resume_key") or "")
    candidates = []
    if run_provenance.get("source_commit"):
        candidates = [r for r in audit.Journal.recover(journal_path, resume_key) if r.finding_id in wanted]
    recovered = [
        r for r in candidates
        if not r.error
        and r.fingerprint == reuse_mod.fingerprint(finding_by_id[r.finding_id])
        and (r.model is None or r.model == provider_cfg.model)
        and not review_policy.selected(finding_by_id[r.finding_id].cwe, cfg.manual_review_cwes)
    ]
    if skipped := len(candidates) - len(recovered):
        print(f"→ mandatory LLM + human review: re-triaging {skipped} recovered verdict(s)", file=sys.stderr)
    if recovered:
        done_ids = {r.finding_id for r in recovered}
        before = len(findings)
        findings = [f for f in findings if f.finding_id not in done_ids]
        print(f"→ resuming an interrupted run: {len(recovered)} verdict(s) already decided, {len(findings)} of {before} left", file=sys.stderr)

    stem = provider_cfg.name
    password_hashers = [item.as_dict() for item in business_logic_inventory.password_hashers] if business_logic_inventory else []
    from ..sca.govulncheck import GovulncheckUnavailable
    client = build_client(provider_cfg)
    try:
        with audit.Journal(journal_path, cfg.prompt_pack, run_provenance) as journal:
            try:
                pipeline = TriagePipeline(client, provider_cfg, cfg, source=source, symbols=symbols,
                                          dependency_manifest_root=manifest_root)
            except GovulncheckUnavailable as exc:
                print(f"error: граф вызовов запрошен, но недоступен — {exc}", file=sys.stderr)
                return 2
            if source_roots:
                print(f"→ стек проекта: {', '.join(s.id for s in pipeline.stacks) or 'не распознан'}",
                      file=sys.stderr)
                for line in pipeline.repository_components:
                    print(f"  · {line}", file=sys.stderr)
            remaining_findings = list(findings)
            current: dict[str, TriageRecord] = {}

            def save_main_record(record):
                journal.append(record)
                current[record.finding_id] = record

            try:
                run = pipeline.run(remaining_findings, progress=progress, on_record=save_main_record)
            except LLMAuthError as exc:
                scoped = scope_filter.apply(remaining_findings, cfg.scope)
                run = TriageRun(
                    records=[current.get(f.finding_id) or _error_record(f, provider_cfg, exc)
                             for f in scoped.kept] + scoped.excluded,
                    provider=provider_cfg.name,
                    model=provider_cfg.model,
                    prompt_pack=cfg.prompt_pack,
                    deployment_config=pipeline.deployment.config_path,
                    deployment_config_sha256=pipeline.deployment.config_sha256,
                    scope_excluded=scoped.counts,
                    spend_usd=float(getattr(client, "spend_usd", 0.0) or 0.0),
                    model_calls=int(getattr(client, "calls", 0) or 0),
                )
                business_error = (
                    f"Основная SAST-фаза прервана: {exc}. Business Logic не запускалась. "
                    "Завершённые и неудачные SAST-находки сохранены в итоговых отчётах."
                )
                print(f"\nerror: {exc}\n       {business_error} Журнал для продолжения: {journal_path}",
                      file=sys.stderr)
            run.records.extend(recovered)
            run.records = [review_policy.enforce(r, cfg.manual_review_cwes) for r in run.records]
            run.coverage = coverage_report.read(findings_path if findings_path.is_dir() else findings_path.parent)
            run.provenance = dict(run_provenance)
            for gap in run.coverage.gaps(): print(f"  ! {gap}", file=sys.stderr)
            audit.write_jsonl(run, out / f"verdicts-{stem}.jsonl")
            audit.write_summary(run, out / f"summary-{stem}.json")
            run_manifest = audit.write_manifest(run, out / f"run-manifest-{stem}.json")
            print(f"→ run manifest: {run_manifest}", file=sys.stderr)
            if (business_logic_audit or business_findings) and not business_error:
                idor_findings = [f for f in business_findings if f.cwe == "CWE-639"]
                other_logic_findings = [f for f in business_findings if f.cwe != "CWE-639"]
                checkpoint = (f"Снимок по завершении SAST. В отдельные очереди передано "
                              f"IDOR {len(idor_findings)}, остальная бизнес-логика {len(other_logic_findings)}.")
                _write_reports(out, run, None, [checkpoint], password_hashers)
                stage_results = []
                for stage_name, stage_findings, stage_path in (
                    ("IDOR", idor_findings, idor_path),
                    ("остальная бизнес-логика", other_logic_findings, business_path),
                ):
                    if not stage_findings:
                        continue
                    _PROGRESS_STATE.clear()
                    calls_before = int(getattr(client, "calls", 0) or 0)
                    spend_before = float(getattr(client, "spend_usd", 0.0) or 0.0)
                    pending = stage_path.with_suffix(".jsonl.partial")
                    by_id = {f.finding_id: f for f in stage_findings}
                    completed = {
                        r.finding_id: r for r in audit.Journal.recover(pending, resume_key)
                        if run_provenance.get("source_commit")
                        and r.finding_id in by_id and r.model == provider_cfg.model and not r.error
                        and r.fingerprint == reuse_mod.fingerprint(by_id[r.finding_id])
                        and not review_policy.selected(by_id[r.finding_id].cwe, cfg.manual_review_cwes)
                    }
                    current = {}
                    try:
                        with audit.Journal(pending, cfg.prompt_pack, run_provenance) as stage_journal:
                            def save_record(record):
                                stage_journal.append(record)
                                current[record.finding_id] = record

                            stage_run = pipeline.run(
                                [f for f in stage_findings if f.finding_id not in completed],
                                progress=progress, on_record=save_record)
                    except Exception as exc:
                        finished = {**completed, **current}
                        business_error = (f"Проверка {stage_name} прервана. Готовых записей "
                                          f"{len(finished)} из {len(stage_findings)}. {type(exc).__name__}: {exc}")
                        print(f"error: {business_error} · журнал {pending}", file=sys.stderr)
                        stage_run = replace(
                            run, records=[finished.get(f.finding_id) or _error_record(f, provider_cfg, exc)
                                          for f in stage_findings],
                            coverage=None, reuse=None, scope_excluded={},
                            model_calls=int(getattr(client, "calls", 0) or 0),
                            spend_usd=float(getattr(client, "spend_usd", 0) or 0))
                    else:
                        stage_run.records.extend(completed.values())
                    stage_run.model_calls -= calls_before
                    stage_run.spend_usd = (stage_run.spend_usd or 0) - spend_before
                    stage_run.provenance = dict(run_provenance)
                    audit.write_jsonl(stage_run, stage_path)
                    audit.write_summary(stage_run, out / f"{stage_path.stem.replace('-verdicts-' + stem, '')}-summary-{stem}.json")
                    stage_results.append(stage_run)
                if stage_results:
                    business_run = replace(run, records=[r for stage in stage_results for r in stage.records],
                                           model_calls=sum(stage.model_calls for stage in stage_results),
                                           spend_usd=sum(stage.spend_usd or 0 for stage in stage_results),
                                           coverage=None, reuse=None, scope_excluded={})
    finally:
        client.close()
        from ..sca.codeql_runner import close_servers
        close_servers()
        if symbols:
            print(f"→ language server: {symbols.stats}", file=sys.stderr)
            symbols.close()
    if source: print(f"→ code context: {source.stats()}", file=sys.stderr)
    business_warnings = list(business_logic_inventory.warnings) if business_logic_inventory else []
    if business_error:
        business_warnings.append(business_error)
    if business_logic_inventory is not None:
        inventory_path = out / f"business-logic-inventory-{stem}.json"
        payload = {
            "password_hashers": password_hashers,
            "endpoints": [endpoint.as_dict() for endpoint in business_logic_inventory.endpoints.endpoints],
            "hash_candidates": [
                {"file_path": path, "line": line, "expression": expression, "cwe": cwe}
                for path, line, expression, cwe in business_logic_inventory.hash_candidates
            ],
            "warnings": business_warnings,
            "files_scanned": business_logic_inventory.files_scanned,
            "testcases_executed": False,
            "findings": [r.model_dump(mode="json") for r in (business_run.records if business_run else [])],
        }
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        inventory_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"→ Business Logic inventory: {inventory_path}", file=sys.stderr)
    report = _write_reports(out, run, business_run, business_warnings, password_hashers)
    if business_error:
        print(report)
        return 2
    journal_path.unlink(missing_ok=True)
    if business_run is not None:
        business_path.with_suffix(".jsonl.partial").unlink(missing_ok=True)
        idor_path.with_suffix(".jsonl.partial").unlink(missing_ok=True)
    from ..report import upgrades as upgrades_mod
    steps = upgrades_mod.plan(run.records)
    if steps:
        (out / f"upgrade-plan-{stem}.json").write_text(
            json.dumps([s.as_dict() for s in steps], ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"→ {upgrades_mod.summary(steps)} -> {out / f'upgrade-plan-{stem}.json'}", file=sys.stderr)
    from ..models import VerdictLabel
    counts = run.counts()
    proven = sum(1 for r in run.in_scope if r.verdict.verdict is VerdictLabel.confirmed and (r.sca is None or r.sca.outcome in _PROVEN_OUTCOMES))
    unproven = counts["confirmed"] - proven
    print(f"\n  доказано {proven} · не закрыто {unproven} · автозакрыто {run.auto_closed} · на человека {sum(1 for r in run.records if r.verdict.requires_human_review)} · corrected {sum(1 for r in run.records if r.overrides)} · errors {sum(1 for r in run.records if r.error)} · ${run.total_cost_usd:.4f}" + (f" ({run.model_calls} запросов)" if run.model_calls else ""), file=sys.stderr)
    total = len(run.in_scope) or 1
    settled = sum(1 for r in run.in_scope if not r.verdict.requires_human_review)
    print(f"  решено без человека: {settled}/{len(run.in_scope)} ({100 * settled / total:.0f}%)",
          file=sys.stderr)
    print(f"  подходят для авторешения: {run.auto_eligible} · автозакрыто {run.auto_closed} · "
          f"решено без человека среди подходящих {run.auto_decided_eligible}/{run.auto_eligible} "
          f"({run.auto_decision_pct:.1f}%)", file=sys.stderr)
    priorities = {p: sum(1 for r in run.records if r.sca is not None and r.sca.priority == p)
                  for p in ("critical", "high", "medium", "low")}
    if any(priorities.values()):
        print("  приоритет зависимостей: " + ", ".join(f"{k} {v}" for k, v in priorities.items()), file=sys.stderr)
    from ..report.audit import _confidence_spread, _stage_seconds
    stages = _stage_seconds(run.records)
    if stages:
        print("  время по этапам (медиана/сумма, с): " + ", ".join(
            f"{k} {v['median']:.0f}/{v['total']:.0f}" for k, v in stages.items()), file=sys.stderr)
    spread = _confidence_spread(run.records)
    if spread.get("stdev") is not None and spread["stdev"] < 0.02:
        print(f"  ! уверенность модели почти не различается (σ={spread['stdev']}, "
              f"{spread['distinct']} значений на {spread['n']} вердиктов) — порог автоприменения ничего не решает",
              file=sys.stderr)
    print(report)
    problems = quality_problems(
        run,
        business_run,
        require_manifest=getattr(args, "cmd", "") == "run",
        dependency_chain_required=cfg.resolve_vulnerable_symbols,
        tool_calling_failed=bool(getattr(client, "_native_tools_rejected", False)),
    )
    if business_logic_audit:
        problems.extend(f"business-logic coverage: {warning}" for warning in business_warnings)
    if problems:
        for problem in problems:
            print(f"  ! incomplete run: {problem}", file=sys.stderr)
        if not getattr(args, "allow_partial", False):
            print("  ✗ quality gate: прогон неполный (exit 2); отчёт сохранён. "
                  "Исправьте покрытие или явно подтвердите деградацию через --allow-partial", file=sys.stderr)
            return 2
        print("  ! --allow-partial: деградированный отчёт принят явно", file=sys.stderr)
    fail_on = getattr(args, "fail_on", "none")
    gate_counts = dict(counts)
    pending_fp = run.false_positive_pending_review
    if business_run is not None:
        for label, count in business_run.counts().items():
            gate_counts[label] += count
        pending_fp += business_run.false_positive_pending_review
    gate_n = gate_count(fail_on, gate_counts, pending_fp)
    if gate_n is not None:
        if gate_n:
            what = "confirmed vuln(s)" if fail_on == "confirmed" else "finding(s) needing review"
            print(f"  ✗ gate --fail-on {fail_on}: {gate_n} {what} — failing the job (exit 1)", file=sys.stderr)
            return 1
        print(f"  ✓ gate --fail-on {fail_on}: clean", file=sys.stderr)
    return 0
