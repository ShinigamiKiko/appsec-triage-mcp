import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from appsec_triage_mcp import server as server_module
from appsec_triage_mcp.jobs import JobManager, Workspace
from appsec_triage_mcp.telegram import TelegramError, TelegramNotifier


def job_result():
    return {
        "job_id": "job-1",
        "kind": "scan",
        "status": "succeeded",
        "duration_s": 12.3,
        "project": "gf-api-gateway",
    }


def test_telegram_requires_token_and_chat(monkeypatch):
    monkeypatch.delenv("APPSEC_MCP_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("APPSEC_MCP_TELEGRAM_CHAT_ID", raising=False)

    with pytest.raises(TelegramError, match="TELEGRAM_BOT_TOKEN"):
        TelegramNotifier.from_env()


def test_telegram_reads_mounted_token(tmp_path, monkeypatch):
    token_path = tmp_path / "telegram.token"
    monkeypatch.delenv("APPSEC_MCP_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.setenv("APPSEC_MCP_TELEGRAM_BOT_TOKEN_FILE", str(token_path))
    with pytest.raises(TelegramError, match="Cannot read"):
        TelegramNotifier.from_env("test-chat")
    token_path.write_text("test-token\n", encoding="utf-8")
    assert TelegramNotifier.from_env("test-chat").token == "test-token"


def test_telegram_message_sends_project_to_bot_api():
    captured = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            captured["path"] = self.path
            captured["body"] = self.rfile.read(int(self.headers["Content-Length"])).decode()
            body = json.dumps({"ok": True, "result": {"message_id": 77}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    api = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=api.serve_forever, daemon=True)
    thread.start()
    try:
        notifier = TelegramNotifier("test-token", "chat-1", f"http://127.0.0.1:{api.server_port}")
        result = notifier.send_result(job_result())
    finally:
        api.shutdown()
        api.server_close()
        thread.join()

    assert captured["path"] == "/bottest-token/sendMessage"
    assert "Project%3Agf-api-gateway" in captured["body"].replace("+", "")
    assert result["project"] == "gf-api-gateway"
    assert result["telegram_message_id"] == 77
    assert result["report_sent"] is False


def test_telegram_document_contains_report_and_project(tmp_path, monkeypatch):
    report = tmp_path / "report-llm-ru.html"
    report.write_text("<html>report</html>", encoding="utf-8")
    captured = {}

    def request(method, fields, **files):
        captured.update(method=method, fields=fields, files=files)
        return {"ok": True, "result": {"message_id": 78}}

    notifier = TelegramNotifier("test-token", "chat-1")
    monkeypatch.setattr(notifier, "_request", request)

    result = notifier.send_result(job_result(), report)

    assert captured["method"] == "sendDocument"
    assert "Project: gf-api-gateway" in captured["fields"]["caption"]
    assert captured["files"]["document"] == (report.name, b"<html>report</html>", "text/html")
    assert result["report_sent"] is True
    assert result["report"] == report.name


class FakeProcess:
    def wait(self):
        return 0

    def poll(self):
        return 0


def test_telegram_result_is_available_through_mcp(tmp_path, monkeypatch):
    source = tmp_path / "gf-api-gateway"
    output = tmp_path / "output"
    source.mkdir()
    output.mkdir()
    manager = JobManager(Workspace(source, output, tmp_path, "agent-python"), popen=lambda *args, **kwargs: FakeProcess())
    started = manager.start("scan", ["scan", str(source), "-o", "{out}"], project=source.name)
    captured = {}

    class FakeNotifier:
        @classmethod
        def from_env(cls, chat_id):
            captured["chat_id"] = chat_id
            return cls()

        def send_result(self, result, report):
            captured["result"] = result
            captured["report"] = report
            return {"job_id": result["job_id"], "project": result["project"], "report_sent": report is not None}

    monkeypatch.setattr(server_module, "_manager", manager)
    monkeypatch.setattr(server_module, "TelegramNotifier", FakeNotifier)

    response = asyncio.run(
        server_module.server.call_tool(
            "appsec_send_telegram_result",
            {"job_id": started["job_id"], "chat_id": "override-chat", "send_report": False},
        )
    )

    assert response.is_error is False
    payload = json.loads(response.content[0].text)
    assert payload["project"] == "gf-api-gateway"
    assert captured["chat_id"] == "override-chat"
    assert captured["result"]["status"] == "succeeded"
    assert captured["report"] is None
