"""Run scanner primitives and render findings, without any LLM agent or provider."""

from __future__ import annotations

import argparse
import html
import json
import os
from collections import Counter
from pathlib import Path


def main() -> int:
    from .repositories import detect_ecosystems

    parser = argparse.ArgumentParser(description="MCP scanner worker, without an LLM agent")
    parser.add_argument("operation", choices=["scan"])
    parser.add_argument("target", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("-s", "--scanner", action="append")
    args = parser.parse_args()
    source = args.target.resolve()
    os.environ["APPSEC_ECOSYSTEMS"] = ",".join(detect_ecosystems(source))
    return run_scan(source, args.output, args.scanner)


def run_scan(source: Path, output: Path, scanners: list[str] | None = None, project: str | None = None) -> int:
    from .core.context import stack
    from .core.ingest import load
    from .core.redact import redact_secrets
    from .core.scanners import scan_all, write_manifest
    from .core.scanners.selection import scanners_for_target
    from .repositories import detect_ecosystems

    selected = scanners or scanners_for_target(source)
    configured = os.environ.get("APPSEC_ECOSYSTEMS", "")
    review_context = {
        "ecosystems": configured.split(",") if configured else detect_ecosystems(source),
        "stacks": [profile.id for profile in stack.detect([source])],
    }
    scan_output = output / "scans"
    scan_output.mkdir(parents=True, exist_ok=True)
    results = scan_all(source, selected, scan_output, on_start=lambda name: print(f"Scanning: {name}", flush=True))
    manifest = write_manifest(source, results, scan_output)
    findings = []
    parse_errors = []
    for result in results:
        if result.ok and result.output_path:
            try:
                findings.extend(item.model_dump(mode="json") for item in load(result.output_path))
            except (OSError, ValueError, RuntimeError, KeyError) as exc:
                parse_errors.append(f"{result.scanner}: {exc}")

    def redacted(value):
        if isinstance(value, str):
            return redact_secrets(value)[0] or ""
        if isinstance(value, dict):
            return {key: redacted(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redacted(item) for item in value]
        return value

    findings = redacted(findings)
    complete = bool(results) and all(item.ok for item in results) and not parse_errors
    summary = {"complete": complete, "analysis": "scanner_findings", "llm_used": False, "review_context": review_context,
               "total_findings": len(findings), "by_severity": dict(Counter(item["severity"] for item in findings)),
               "scanners": [item.as_dict() for item in results], "parse_errors": parse_errors}
    (output / "summary-scan.json").write_text(json.dumps(redacted(summary), ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "findings-scan.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in findings), encoding="utf-8")
    body = render_report(project or source.name, findings, redacted(summary))
    (output / "report-scan.html").write_text(body, encoding="utf-8")
    print(f"HTML report: {output / 'report-scan.html'}; manifest: {manifest}", flush=True)
    return 0 if complete else 1


def render_report(project: str, findings: list[dict], summary: dict) -> str:
    escape = lambda value: html.escape(str(value))
    scans = "".join(
        f"<tr><td>{escape(item['scanner'])}</td><td>{'OK' if item['ok'] else 'FAILED'}</td>"
        f"<td>{escape(item.get('version') or '—')}</td><td>{escape(item.get('findings', 0))}</td>"
        f"<td>{escape(item.get('error') or item.get('note') or '')}</td></tr>" for item in summary["scanners"])
    cards = []
    for index, finding in enumerate(findings, 1):
        context = finding.get("code_context") or {}
        cards.append(
            f"<article><h2>{index}. {escape(finding.get('title') or finding.get('rule_id') or 'Finding')}</h2>"
            f"<p><strong>{escape(finding.get('severity'))}</strong> · {escape(finding.get('cwe') or 'CWE unknown')}"
            f" · {escape(finding.get('scanner'))}</p>"
            f"<p><code>{escape(context.get('file_path', ''))}:{escape(context.get('start_line', ''))}</code></p>"
            f"<p>{escape(finding.get('message') or finding.get('description') or '')}</p>"
            f"<pre>{escape(context.get('snippet') or '')}</pre>"
            f"<details><summary>Finding data</summary><pre>{escape(json.dumps(finding, ensure_ascii=False, indent=2))}"
            "</pre></details></article>")
    errors = "".join(f"<li>{escape(item)}</li>" for item in summary.get("parse_errors", []))
    state = "Сканирование завершено" if summary["complete"] else "Сканирование неполное"
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
        f"<title>{escape(project)} — AppSec</title>"
        '<style>body{max-width:1100px;margin:40px auto;padding:0 24px;font:16px/1.5 system-ui;color:#17213a}'
        'table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:10px;border-bottom:1px solid #ddd}'
        'article{margin:28px 0;padding-top:10px;border-top:2px solid #d9e1ed}'
        'pre{padding:14px;background:#f3f5f8;white-space:pre-wrap;overflow-wrap:anywhere}'
        'code{overflow-wrap:anywhere}h1,h2{line-height:1.25}</style></head><body>'
        f"<h1>{escape(project)}</h1><p><strong>{state}</strong> · Находок: {len(findings)}</p>"
        '<p>Результаты сканеров. Приоритеты и описания приведены инструментами; '
        'подтверждение уязвимостей и анализ моделью MCP-клиента выполняются отдельно.</p>'
        '<table><thead><tr><th>Сканер</th><th>Статус</th><th>Версия</th><th>Находки</th><th>Примечания</th></tr>'
        f"</thead><tbody>{scans}</tbody></table><ul>{errors}</ul>"
        + ("".join(cards) if cards else "<p>Сканеры не вернули находок.</p>")
        + "</body></html>"
    )


if __name__ == "__main__":
    raise SystemExit(main())
