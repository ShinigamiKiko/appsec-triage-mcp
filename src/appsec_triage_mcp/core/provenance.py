"""Self-contained provenance for a stateless analysis job."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from importlib import metadata
from pathlib import Path

from .config import CONFIG_DIR, ProviderConfig
from .prompts import registry


def file_sha256(path: Path | str | None) -> str | None:
    if path is None:
        return None
    path = Path(path)
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def tree_sha256(paths: list[Path], *, root: Path | None = None) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: str(item)):
        name = path.relative_to(root).as_posix() if root is not None else path.name
        digest.update(name.encode("utf-8"))
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<unreadable>")
    return digest.hexdigest()


def input_sha256(path: Path) -> str:
    if path.is_file():
        return file_sha256(path) or ""
    files = [
        item for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() in {".json", ".jsonl", ".ndjson", ".sarif"}
        and not any(part.startswith(".") for part in item.relative_to(path).parts)
        and item.name != "scan-manifest.json"
    ]
    digest = hashlib.sha256()
    for item in sorted(files):
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(item.read_bytes())
    return digest.hexdigest()


def create(*, findings_path: Path, source_roots: list[Path], pipeline_path: Path | None,
           lsp_path: Path | None, deployment_path: Path | str | None,
           provider: ProviderConfig, prompt_pack: str,
           dependency_manifest_root: Path | None = None) -> dict[str, object]:
    pipeline_path = pipeline_path or CONFIG_DIR / "pipeline.yaml"
    lsp_path = lsp_path or CONFIG_DIR / "lsp.yaml"
    prompts_root = registry.PROMPTS_ROOT
    code_root = Path(__file__).resolve().parent
    code_files = list(code_root.rglob("*.py"))
    prompt_files = [
        *(prompts_root / prompt_pack).glob("*.md"),
        *(prompts_root / "context").glob("*.md"),
        *(prompts_root / "sca").glob("*.md"),
        *(prompts_root / "stacks").glob("*.md"),
    ]
    try:
        agent_version = metadata.version("appsec-triage")
    except metadata.PackageNotFoundError:
        agent_version = "unknown"
    result: dict[str, object] = {
        "run_id": uuid.uuid4().hex,
        "agent_version": agent_version,
        "source_commit": os.environ.get("CI_COMMIT_SHA") or os.environ.get("SOURCE_COMMIT") or "",
        "source_roots": [str(Path(root).resolve()) for root in source_roots],
        "ecosystems": sorted(part.strip().lower() for part in os.environ.get("APPSEC_ECOSYSTEMS", "").split(",")
                             if part.strip()),
        "input_sha256": input_sha256(findings_path),
        "scanner_manifest_sha256": file_sha256(
            (findings_path if findings_path.is_dir() else findings_path.parent) / "scan-manifest.json"
        ),
        "pipeline_config_sha256": file_sha256(pipeline_path),
        "provider_config_sha256": file_sha256(CONFIG_DIR / "providers" / "llm.yaml"),
        "lsp_config_sha256": file_sha256(lsp_path),
        "prompt_bundle_sha256": tree_sha256(prompt_files, root=prompts_root),
        "agent_code_sha256": tree_sha256(code_files, root=code_root),
        "provider_base_url": provider.base_url,
        "provider_external": provider.external,
        "provider_model": provider.model,
        "deployment_config_sha256": file_sha256(deployment_path),
    }
    if dependency_manifest_root is not None:
        result["dependency_manifest_root"] = str(dependency_manifest_root)
        result["dependency_manifest_hashes"] = {
            name: file_sha256(dependency_manifest_root / name)
            for name in ("package.json", "yarn.lock", "package-lock.json", "composer.json",
                         "composer.lock", "go.mod", "go.sum", "requirements.txt")
            if (dependency_manifest_root / name).is_file()
        }
    resume_material = {key: value for key, value in result.items() if key != "run_id"}
    result["resume_key"] = hashlib.sha256(
        json.dumps(resume_material, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()
    return result
