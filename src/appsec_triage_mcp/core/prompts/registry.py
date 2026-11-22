"""Prompt registry: pick the CWE-specific prompt, fall back to base."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from ..config import REPO_ROOT

PROMPTS_ROOT = REPO_ROOT / "prompts"
TRAINING_CONTEXT_PATH = PROMPTS_ROOT / "context"
_COMMON_CONTEXT = "common"
_ECOSYSTEM_FILE = {"golang": "go", "packagist": "composer", "python": "pypi", "java": "maven"}
_FRONT_MATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


@dataclass(slots=True, frozen=True)
class Prompt:
    id: str
    version: str
    applies_to: tuple[str, ...]
    body: str
    extends: str | None
    includes: tuple[str, ...]
    shared: bool
    kind: str | None
    path: Path

    @property
    def is_catch_all(self) -> bool:
        return "*" in self.applies_to


class PromptError(RuntimeError):
    pass


def _asset_path(directory: Path, name: str, suffix: str = "") -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
        raise PromptError("Invalid bundled prompt name")
    path = (directory / (name + suffix)).resolve()
    if path.parent != directory.resolve():
        raise PromptError("Prompt path is outside its bundled directory")
    return path


def context_part(name: str) -> str:
    """Read the common review context or one bundled ecosystem's context."""
    path = _asset_path(TRAINING_CONTEXT_PATH, name, ".md")
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PromptError(f"{path}: context not read ({exc})") from exc
    if not text:
        raise PromptError(f"{path}: context is empty")
    return text


def context_ecosystems() -> tuple[str, ...]:
    """Every ecosystem that has its own context file."""
    return tuple(sorted(p.stem for p in TRAINING_CONTEXT_PATH.glob("*.md") if p.stem != _COMMON_CONTEXT))


def active_ecosystems() -> tuple[str, ...]:
    """The ecosystem parts this run's prompts carry, from APPSEC_ECOSYSTEMS.

    Unset, every part is carried — the context as it was before it was split.
    An ecosystem without a file of its own gets the common part only.
    """
    raw = os.getenv("APPSEC_ECOSYSTEMS", "")
    available = context_ecosystems()
    if not raw.strip():
        return available
    wanted = []
    for name in (e.strip().lower() for e in raw.split(",") if e.strip()):
        name = _ECOSYSTEM_FILE.get(name, name)
        if name in available and name not in wanted:
            wanted.append(name)
    return tuple(wanted)


@lru_cache(maxsize=8)
def _context(ecosystems: tuple[str, ...]) -> str:
    return "\n\n".join(context_part(name) for name in (_COMMON_CONTEXT, *ecosystems))


def training_context() -> str:
    """Trusted project context for model requests: the common part and this run's ecosystems."""
    return _context(active_ecosystems())


def all_training_context() -> str:
    """Every part, whatever APPSEC_ECOSYSTEMS says — what the agent's own code reads."""
    return _context(context_ecosystems())


ANSWER_LANGUAGE = """## Язык ответа

Все объяснения, обоснования и выводы пиши по-русски.

Оставляй без перевода, ровно как во входных данных:
- цитаты (поля `quote`, `evidence` и любые другие дословные выдержки);
- имена функций, классов, методов, файлов, пакетов, версий;
- идентификаторы advisory (CVE, GHSA, GO-), сообщения сканеров, значения полей.

Цитата сверяется с исходным текстом посимвольно. Переведённая цитата не
проходит сверку, и вместе с ней отбрасывается весь вывод, который на неё
опирался. Если цитата на английском — так её и приводи."""


def _with_training_context(system: str, ecosystems: tuple[str, ...] | None = None) -> str:
    return ("\n\n---\n\n## Project-specific context\n\n" +
            (training_context() if ecosystems is None else _context(ecosystems))
            + "\n\n---\n\n" + system + "\n\n---\n\n" + ANSWER_LANGUAGE)


def _parse(path: Path) -> Prompt:
    text = path.read_text(encoding="utf-8")
    m = _FRONT_MATTER.match(text)
    if not m:
        raise PromptError(f"{path}: missing YAML front matter (--- id/version/applies_to ---)")
    meta = yaml.safe_load(m.group(1)) or {}
    for key in ("id", "version", "applies_to"):
        if key not in meta:
            raise PromptError(f"{path}: front matter is missing required key '{key}'")
    return Prompt(
        id=str(meta["id"]),
        version=str(meta["version"]),
        applies_to=tuple(str(c).upper() for c in meta["applies_to"]),
        body=text[m.end():].strip(),
        extends=meta.get("extends"),
        includes=tuple(meta.get("includes") or []),
        shared=bool(meta.get("shared", False)),
        kind=(str(meta["kind"]) if meta.get("kind") else None),
        path=path,
    )


@lru_cache(maxsize=8)
def load_pack(pack: str = "default") -> dict[str, Prompt]:
    root = _asset_path(PROMPTS_ROOT, pack)
    if not root.is_dir():
        available = sorted(p.name for p in PROMPTS_ROOT.iterdir() if p.is_dir()) if PROMPTS_ROOT.is_dir() else []
        raise PromptError(f"no prompt pack '{pack}' at {root}. Available: {available}")
    prompts = {p.id: p for p in (_parse(f) for f in sorted(root.glob("*.md")))}
    if "base" not in prompts:
        raise PromptError(f"prompt pack '{pack}' has no base.md")
    return prompts


def normalize_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    m = re.search(r"(\d+)", str(cwe))
    return f"CWE-{m.group(1)}" if m else str(cwe).upper()


def _matching_cwes(prompts: dict[str, Prompt], cwe: str | None) -> list[Prompt]:
    key = normalize_cwe(cwe)
    return [p for p in prompts.values() if key in p.applies_to and not p.is_catch_all and not p.shared]


def resolve(cwe: str | None, pack: str = "default", kind: str | None = None) -> Prompt:
    """Most specific prompt for this finding: `kind` first, then CWE, then base."""
    prompts = load_pack(pack)
    if kind:
        for prompt in prompts.values():
            if prompt.kind == kind:
                return prompt
    matches = _matching_cwes(prompts, cwe)
    if matches:
        return min(matches, key=lambda p: len(p.applies_to))
    return prompts["base"]


def review_prompts(cwe: str | None, pack: str = "default", kind: str | None = None) -> list[Prompt]:
    """Order client review templates from base through CWE family, specific CWE and finding kind."""
    prompts = load_pack(pack)
    ordered: list[Prompt] = []
    included: set[str] = set()
    visiting: set[str] = set()

    def add(prompt_id: str) -> None:
        if prompt_id in included:
            return
        if prompt_id in visiting:
            raise PromptError(f"Circular template reference to '{prompt_id}' in pack '{pack}'")
        if prompt_id not in prompts:
            raise PromptError(f"Unknown template '{prompt_id}' referenced in pack '{pack}'")
        visiting.add(prompt_id)
        prompt = prompts[prompt_id]
        if prompt.extends:
            add(prompt.extends)
        ordered.append(prompt)
        for fragment in prompt.includes:
            add(fragment)
        visiting.remove(prompt_id)
        included.add(prompt_id)

    add("base")
    for prompt in sorted(_matching_cwes(prompts, cwe), key=lambda p: -len(p.applies_to)):
        add(prompt.id)
    if kind:
        for prompt in prompts.values():
            if prompt.kind == kind and not prompt.shared:
                add(prompt.id)
    return ordered


def render_system(
    cwe: str | None, pack: str = "default", stack_section: str = "", kind: str | None = None,
    ecosystems: tuple[str, ...] | None = None,
) -> tuple[str, Prompt]:
    """Compose the system prompt: base + CWE specialization + stack conventions."""
    prompt = resolve(cwe, pack, kind)
    parts: list[str] = []
    if prompt.kind and not prompt.extends:
        parts.append(load_pack(pack)["base"].body)
    if prompt.extends:
        parent = load_pack(pack).get(prompt.extends)
        if parent is None:
            raise PromptError(f"{prompt.path}: extends unknown prompt '{prompt.extends}'")
        parts.append(parent.body)
    parts.append(prompt.body)
    for frag_id in prompt.includes:
        fragment = load_pack(pack).get(frag_id)
        if fragment is None:
            raise PromptError(f"{prompt.path}: includes unknown fragment '{frag_id}'")
        parts.append(fragment.body)
    if stack_section:
        parts.append(stack_section)
    return _with_training_context("\n\n---\n\n".join(parts), ecosystems), prompt


def with_context(system: str) -> str:
    """Any system prompt with this run's project context: the common part and each ecosystem."""
    return _with_training_context(system.strip())


def step(name: str) -> str:
    """The system prompt for one dependency-triage step, by file name.

    Built at each call, not at import: modules that hold a step prompt are imported
    while the CLI parser is built, before `.env` is read, and a prompt frozen then
    would carry every ecosystem while the rest of the run carries the selected ones.
    """
    return _with_training_context(_step_body(name))


@lru_cache(maxsize=32)
def _step_body(name: str) -> str:
    path = _asset_path(PROMPTS_ROOT / "sca", name, ".md")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PromptError(f"{path}: промпт шага не прочитан ({exc})") from exc
    match = _FRONT_MATTER.match(text)
    body = text[match.end():] if match else text
    if not body.strip():
        raise PromptError(f"{path}: промпт пуст")
    return body.strip()


def coverage(pack: str = "default") -> dict[str, str]:
    """CWE -> prompt id, for the report and for spotting gaps."""
    out: dict[str, str] = {}
    for p in load_pack(pack).values():
        if p.shared:
            continue
        for cwe in p.applies_to:
            if cwe != "*":
                out[cwe] = p.id
    return dict(sorted(out.items()))
