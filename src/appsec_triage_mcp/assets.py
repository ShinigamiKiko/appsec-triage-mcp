"""Bundled prompts and configuration exposed to the MCP client's model."""

from __future__ import annotations

import hashlib
import re
from typing import Literal

import yaml

from .core.config import REPO_ROOT
from .core.context import stack
from .core.prompts import registry
from .core.validate.schema import VERDICT_SCHEMA
from .jobs import JobError

AssetKind = Literal["prompts", "configs"]


def asset_index(kind: AssetKind) -> list[dict]:
    root = REPO_ROOT / kind
    return [{"name": path.relative_to(root).as_posix(), "bytes": path.stat().st_size,
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(root.rglob("*")) if path.is_file()]


def read_asset(kind: AssetKind, name: str) -> str:
    if kind not in {"prompts", "configs"}:
        raise JobError("kind must be prompts or configs")
    root = (REPO_ROOT / kind).resolve()
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise JobError("Asset must be an existing file inside the bundled prompts/configs")
    # Return the versioned text, without expanding environment variables or secrets.
    return path.read_text(encoding="utf-8")


DeploymentProfile = Literal["generic", "bundled"]


def review_instructions(cwe: str | None = None, pack: str = "default", kind: str | None = None,
                        ecosystems: list[str] | None = None, stacks: list[str] | None = None,
                        deployment_profile: DeploymentProfile = "generic") -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", pack):
        raise JobError("Invalid prompt pack name")
    known = {"npm", "composer", "pypi", "go", "maven", "rubygems", "cargo", "nuget"}
    selected = set(ecosystems or [])
    if selected - known:
        raise JobError("Unknown ecosystem")
    profiles = {p.id: p for p in stack.load_all()} if stacks else {}
    if set(stacks or []) - profiles.keys():
        raise JobError("Unknown framework profile")
    templates = registry.review_prompts(cwe, pack, kind)
    prompt = registry.resolve(cwe, pack, kind)
    layers = [p.path.relative_to(REPO_ROOT).as_posix() for p in templates]
    parts = [p.body for p in templates]
    for name in ["common", *sorted(selected.intersection(registry.context_ecosystems()))]:
        layers.append(f"prompts/context/{name}.md")
        parts.append(registry.context_part(name))
    frameworks = [profiles[name] for name in sorted(set(stacks or []))]
    if frameworks:
        layers.extend(p.path.relative_to(REPO_ROOT).as_posix() for p in frameworks)
        parts.append(stack.render(frameworks))
    if deployment_profile == "bundled":
        contract = yaml.safe_load(read_asset("configs", "deployment.yaml"))
        if contract.get("enabled"):
            layers.append("configs/deployment.yaml")
            parts.append("Deployment contract selected by the operator for this project. Apply each rule only "
                         "when its prerequisites hold. Check repository-specific conditions and reopening markers.\n"
                         + yaml.safe_dump(contract, allow_unicode=True, sort_keys=False))
    elif deployment_profile != "generic":
        raise JobError("Unknown deployment profile")
    policy = yaml.safe_load(read_asset("configs", "pipeline.yaml"))
    review_policy = {key: policy[key] for key in (
        "scope", "manual_review_cwes", "heuristics", "post_validation", "verification"
    ) if key in policy}
    workflow = (
        "For each scanner finding, collect static evidence with the MCP code tools on the retained source_target. "
        "Then apply the base rules and every supplied supplement to that finding. A supplement tells you what to "
        "check. Establish applicability from the evidence for this component. If evidence cannot resolve a "
        "material conflict, return unknown and name the missing fact. Follow the review_policy and verdict_schema "
        "for the individual verdict. Finally assemble the project report and call appsec_save_result with "
        "source_job_id to release the checkout."
    )
    return {"prompt_id": prompt.id, "version": prompt.version, "cwe": registry.normalize_cwe(cwe),
            "prompt_asset": prompt.path.relative_to(REPO_ROOT / "prompts").as_posix(),
            "layers": layers, "deployment_profile": deployment_profile,
            "instructions": "\n\n".join([workflow, *parts, registry.ANSWER_LANGUAGE]),
            "review_policy": review_policy, "verdict_schema": VERDICT_SCHEMA, "execution": "connected_mcp_client"}
