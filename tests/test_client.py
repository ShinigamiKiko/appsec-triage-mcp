import asyncio
from types import SimpleNamespace

from mcp import Client

from appsec_triage_mcp import server as server_module
from appsec_triage_mcp.client import call, download_report


def test_batch_list_round_trips_through_mcp(monkeypatch):
    expected = [{"job_id": "a", "project": "one"}, {"job_id": "b", "project": "two"}]
    monkeypatch.setattr(server_module, "_manager", SimpleNamespace(start_repositories=lambda *a, **k: expected))

    async def check():
        async with Client(server_module.server, mode="legacy") as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            assert not {"appsec_start_run", "appsec_start_triage", "appsec_start_doctor"} & tools.keys()
            assert "mode" not in tools["appsec_start_repository_scan"].input_schema["properties"]
            return await call(client, "appsec_start_repository_scan", {"projects": "https://host/a,https://host/b"})

    assert asyncio.run(check()) == expected


def test_download_report_reassembles_unicode_pages(tmp_path):
    text = "<html>Привет</html>"

    class FakeClient:
        async def call_tool(self, name, args, **kwargs):
            offset = args["offset"]
            chunk = text[offset:offset + 5]
            return SimpleNamespace(is_error=False, structured_content={
                "text": chunk, "truncated": offset + len(chunk) < len(text), "next_offset": offset + len(chunk)},
                content=[])

    path = asyncio.run(download_report(FakeClient(), {"job_id": "abc", "project": "demo"}, tmp_path))
    assert path.read_text(encoding="utf-8") == text
