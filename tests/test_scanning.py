import json
from types import SimpleNamespace

from appsec_triage_mcp.scanning import run_scan


def test_scanner_html_contains_findings_without_llm_configuration(tmp_path, monkeypatch):
    from appsec_triage_mcp.core import ingest, scanners
    from appsec_triage_mcp.core.scanners.base import ScanResult

    for name in ("LLM_API_KEY", "LLM_MODEL", "LLM_BASE_URL", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.delenv("APPSEC_ECOSYSTEMS", raising=False)
    (source / "package.json").write_text('{"dependencies":{"express":"5"}}')
    output = tmp_path / "output"
    output.mkdir()
    sarif = output / "scan.sarif"
    sarif.write_text("{}")
    monkeypatch.setattr(scanners, "scan_all", lambda *a, **k: [
        ScanResult("opengrep", True, output_path=sarif, findings=1)])
    finding = {"severity": "high", "cwe": "CWE-79", "scanner": "opengrep", "rule_id": "xss",
               "code_context": {"file_path": "src/index.js", "start_line": 12, "snippet": "<script>alert(1)</script>"}}
    monkeypatch.setattr(ingest, "load", lambda *a: [SimpleNamespace(model_dump=lambda **k: finding)])

    assert run_scan(source, output, ["opengrep"], project="demo") == 0
    report = (output / "report-scan.html").read_text(encoding="utf-8")
    assert "CWE-79" in report and "src/index.js:12" in report and "demo" in report
    assert "<script>" not in report
    summary = json.loads((output / "summary-scan.json").read_text(encoding="utf-8"))
    assert summary["llm_used"] is False
    assert summary["review_context"] == {"ecosystems": ["npm"], "stacks": ["express"]}
    assert summary["by_severity"] == {"high": 1}
