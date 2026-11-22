import asyncio
import importlib.util
import json

import pytest
from mcp import Client

from appsec_triage_mcp.assets import asset_index, read_asset, review_instructions
from appsec_triage_mcp.client import call
from appsec_triage_mcp.core.config import CONFIG_DIR
from appsec_triage_mcp.core.prompts import registry
from appsec_triage_mcp.jobs import JobError, Workspace
from appsec_triage_mcp.server import server


def test_resources_resolve_inside_the_mcp_package(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APPSEC_AGENT_ROOT", str(tmp_path / "nonexistent-agent"))
    monkeypatch.setenv("APPSEC_MCP_SOURCE_ROOT", str(tmp_path / "source"))
    monkeypatch.setenv("APPSEC_MCP_OUTPUT_ROOT", str(tmp_path / "output"))
    workspace = Workspace.from_env()
    assert workspace.runtime_root.is_dir()
    assert "appsec_triage_mcp" in str(CONFIG_DIR)
    assert (CONFIG_DIR / "pipeline.yaml").is_file()
    assert (registry.PROMPTS_ROOT / "default" / "base.md").is_file()
    assert "base" in registry.load_pack()
    assert importlib.util.find_spec("appsec_triage") is None


@pytest.mark.parametrize("kind,name", [
    ("configs", "../config.py"), ("prompts", "../../jobs.py"), ("configs", "/etc/passwd"),
])
def test_asset_reads_cannot_escape_bundle(kind, name):
    with pytest.raises(JobError, match="inside the bundled"):
        read_asset(kind, name)


def test_prompts_and_policies_are_rendered_for_the_client_without_env_mutation(monkeypatch):
    monkeypatch.setenv("APPSEC_ECOSYSTEMS", "composer")
    one = review_instructions("CWE-79", ecosystems=["npm"])
    two = review_instructions("CWE-89", ecosystems=["go"])
    assert one["execution"] == "connected_mcp_client"
    assert one["prompt_id"]
    assert "manual_review_cwes" in one["review_policy"]
    assert "source_job_id" in two["instructions"]
    import os
    assert os.environ["APPSEC_ECOSYSTEMS"] == "composer"
    assert any(item["name"] == "scanners/opengrep.yaml" for item in asset_index("configs"))


def test_layers_compose_base_cwe_dependency_and_only_applicable_context(monkeypatch):
    monkeypatch.setenv("APPSEC_ECOSYSTEMS", "go")
    generic = review_instructions("CWE-99999")
    assert generic["layers"] == ["prompts/default/base.md", "prompts/context/common.md"]
    selected = review_instructions("CWE-328", kind="dependency", ecosystems=["npm"], stacks=["express"])
    expected = ["default/base", "default/crypto", "default/_sanitizers", "default/cwe-328", "default/sca",
                "context/common", "context/npm", "stacks/express"]
    assert selected["layers"] == [f"prompts/{path}.md" for path in expected]
    for prompt in registry.review_prompts("CWE-328", kind="dependency"):
        assert selected["instructions"].count(prompt.body) == 1
    assert "no_ssh_in_workloads" not in selected["instructions"]
    contract = review_instructions(deployment_profile="bundled")
    assert "no_ssh_in_workloads: true" in contract["instructions"]
    assert "markers_reopen: true" in contract["instructions"]
    assert "verdict" in selected["verdict_schema"]["required"]


def test_config_api_never_expands_secret_environment_values(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "private-test-value")
    text = read_asset("configs", "providers/llm.yaml")
    assert "private-test-value" not in text
    assert "${LLM_API_KEY" in text


def test_native_mcp_prompt_and_asset_tools_are_available():
    async def check():
        async with Client(server, mode="legacy") as client:
            prompts = await client.list_prompts()
            assert "appsec_review" in {prompt.name for prompt in prompts.prompts}
            result = await client.get_prompt("appsec_review", {"cwe": "CWE-79", "ecosystems": "npm"})
            assert "Review policy" in result.messages[0].content.text
            args = {"kind": "dependency", "cwe": "CWE-79", "stacks": ["express"]}
            data = await call(client, "appsec_get_review_instructions", args)
            prompt = await client.get_prompt("appsec_review", {**args, "stacks": "express"})
            assert data["instructions"] in prompt.messages[0].content.text
            assets = await client.call_tool("appsec_list_assets", {"kind": "prompts"})
            assert not assets.is_error
            result = await client.read_resource("appsec://assets")
            assert "default/base.md" in result.contents[0].text

    asyncio.run(check())


def test_vendor_manifest_contains_every_imported_source_file():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "docs" / "vendor-manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["files"]) == 224
    assert all(".env" not in item["source"].split("/") for item in manifest["files"])
    assert all((root / item["bundled"]).is_file() for item in manifest["files"])
