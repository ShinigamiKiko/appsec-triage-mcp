"""Lexical helpers shared by the Go and JavaScript route readers.

Neither reader builds a syntax tree. They find a registration with a regular
expression and then read its argument list bracket by bracket, skipping
strings and comments, which is enough to split `r.GET("/x", auth(), h.Get)`
into a path, middleware and a handler.
"""

from __future__ import annotations

import os
import re
from bisect import bisect_right
from collections.abc import Iterator
from pathlib import Path

SKIP_DIRS = {
    ".git", "vendor", "node_modules", "var", "cache", "build", "dist", "coverage",
    ".next", ".nuxt", ".svelte-kit", "testdata", "__tests__", "__mocks__", "__fixtures__",
    "__snapshots__", "cypress", "e2e", "mocks",
}
MAX_FILE_BYTES = 1_000_000

_PAIRS = {"(": ")", "{": "}", "[": "]"}
_CLOSERS = set(_PAIRS.values())


def walk(root: Path, suffixes: tuple[str, ...]) -> Iterator[Path]:
    """Source files under `root`, never descending into dependency or build trees."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
                             and not d.startswith("appsec-out"))
        for name in sorted(filenames):
            if not name.startswith("._") and name.endswith(suffixes):
                yield Path(dirpath) / name


def read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


class Lines:
    """Offset to 1-based line number, without recounting newlines each time."""

    def __init__(self, text: str) -> None:
        self.starts = [0, *(m.end() for m in re.finditer("\n", text))]

    def at(self, offset: int) -> int:
        return bisect_right(self.starts, offset)

    @property
    def count(self) -> int:
        return len(self.starts)


def _skip_string(text: str, i: int) -> int:
    """Index just past the string literal opening at `i`."""
    quote, j, n = text[i], i + 1, len(text)
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == quote:
            return j + 1
        if c == "\n" and quote != "`":
            return i + 1  # not a string after all (a stray apostrophe); move on
        j += 1
    return n


def _skip_comment(text: str, i: int) -> int:
    """Index just past a comment starting at `i`, or `i` if there is none."""
    if text.startswith("//", i):
        j = text.find("\n", i)
        return len(text) if j < 0 else j
    if text.startswith("/*", i):
        j = text.find("*/", i + 2)
        return len(text) if j < 0 else j + 2
    return i


def mask(text: str, *, strings: bool = True) -> str:
    """Blank comments and optionally strings while preserving source offsets."""
    out = list(text)
    i = 0
    while i < len(text):
        end = _skip_comment(text, i) if text[i] == "/" else i
        if strings and text[i] in "\"'`":
            end = _skip_string(text, i)
        if end > i:
            out[i:end] = [c if c == "\n" else " " for c in text[i:end]]
            i = end
        elif not strings and text[i] in "\"'`":
            i = _skip_string(text, i)
        else:
            i += 1
    return "".join(out)


class Blocks:
    """Lexical brace scopes for checking registration order."""

    def __init__(self, code: str) -> None:
        self.starts = [0]
        self.scopes = [-1]
        stack = [-1]
        for match in re.finditer(r"[{}]", code):
            if match[0] == "{":
                stack.append(match.start())
            elif len(stack) > 1:
                stack.pop()
            self.starts.append(match.end())
            self.scopes.append(stack[-1])

    def at(self, offset: int) -> int:
        return self.scopes[bisect_right(self.starts, offset) - 1]


def join_path(prefix: str, path: str) -> str:
    return f"{prefix.rstrip('/')}/{path.lstrip('/')}" if prefix else path


def close_of(text: str, start: int) -> int:
    """Index of the bracket closing the one at `start`, or -1 when unbalanced."""
    if start < 0 or start >= len(text) or text[start] not in _PAIRS:
        return -1
    stack = [_PAIRS[text[start]]]
    i, n = start + 1, len(text)
    while i < n:
        c = text[i]
        if c in "\"'`":
            i = _skip_string(text, i)
            continue
        if c == "/" and (j := _skip_comment(text, i)) != i:
            i = j
            continue
        if c in _PAIRS:
            stack.append(_PAIRS[c])
        elif c in _CLOSERS:
            if c != stack.pop():
                return -1
            if not stack:
                return i
        i += 1
    return -1


def split_args(text: str, open_: int, close: int) -> list[tuple[int, int]]:
    """(start, end) of each top-level argument between two brackets."""
    parts, depth, i, seg = [], 0, open_ + 1, open_ + 1
    while i < close:
        c = text[i]
        if c in "\"'`":
            i = _skip_string(text, i)
            continue
        if c == "/" and (j := _skip_comment(text, i)) != i:
            i = j
            continue
        if c in _PAIRS:
            depth += 1
        elif c in _CLOSERS:
            depth -= 1
        elif c == "," and depth == 0:
            parts.append((seg, i))
            seg = i + 1
        i += 1
    parts.append((seg, close))
    out = []
    for s, e in parts:
        while s < e and text[s].isspace():
            s += 1
        while e > s and text[e - 1].isspace():
            e -= 1
        if s < e:
            out.append((s, e))
    return out


_NAME_CHAIN = re.compile(r"^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$")
_CALLEE = re.compile(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\(")


def string_value(expr: str) -> str | None:
    """The value of a plain string literal, or None for anything else."""
    expr = expr.strip()
    if len(expr) < 2 or expr[0] not in "\"'`" or expr[-1] != expr[0] or _skip_string(expr, 0) != len(expr):
        return None
    value = expr[1:-1]
    return None if "\\" in value or (expr[0] == "`" and "${" in value) else value


def is_name(expr: str) -> bool:
    """`h`, `h.Get`, `handlers.user.Get` — a reference, not a call or a literal."""
    return bool(_NAME_CHAIN.match(expr.strip()))


def name_parts(expr: str) -> list[str]:
    return [p for p in re.split(r"\s*\.\s*", expr.strip()) if p]


def as_call(text: str, start: int, end: int) -> tuple[str, list[tuple[int, int]]] | None:
    """`callee(args)` filling exactly [start, end): the callee and its argument spans."""
    match = _CALLEE.match(text, start)
    if not match or match.end() > end:
        return None
    open_ = match.end() - 1
    if close_of(text, open_) != end - 1:
        return None
    return re.sub(r"\s+", "", text[start:open_]), split_args(text, open_, end - 1)


def short(expr: str, limit: int = 60) -> str:
    flat = " ".join(expr.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def posix(path: Path | str) -> str:
    return str(path).replace("\\", "/")
