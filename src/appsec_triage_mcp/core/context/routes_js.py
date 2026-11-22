"""Express registrations in JavaScript and TypeScript source."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path

from ..testpaths import is_test
from ..sca.lang.js import JavaScriptRules
from . import routes_scan as scan
from .routes import Route

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
_APP_IMPORT = re.compile(
    r"""\b(?:import\s+(?:\*\s+as\s+)?(\w+)(?:\s*,\s*\{[^}]*\})?\s+from\s*"""
    r"""|(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*)['"]express['"]"""
)
_ROUTER_IMPORT = re.compile(r"""\bimport\s+(?:\w+\s*,\s*)?\{([^}]+)\}\s*from\s*['"]express['"]""")
_ROUTER_NAME = re.compile(r"(?:^|,)\s*Router(?:\s+as\s+(\w+))?\s*(?=,|$)")
_BIND = re.compile(r"\b(?:const|let|var)\s+(\w+)(?:\s*:\s*[\w.]+)?\s*=\s*([\w.]+)\s*\(")
_CALL = re.compile(r"(?<![\w$.])(\w+)\.(get|post|put|patch|delete|options|head|all|use)\s*\(")
_FUNCTION = re.compile(r"\b(?:async\s+)?function\s+(\w+)\s*\(")
_ARROW = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?=(?:async\s+)?(?:\(|\w+\s*=>))")
_CALLBACK = re.compile(r"(?:async\s+)?(?:function\b|\(|[\w$]+\s*=>)")
_DEFAULT_EXPORT = re.compile(r"(?m)^[ \t]*(?:export[ \t]+default|module\.exports\s*=)\s*(\w+)\s*(?:;|$)")
_NAMED_EXPORT = re.compile(r"(?m)^[ \t]*(?:module\.)?exports\.(\w+)\s*=\s*(\w+)\s*(?:;|$)")
_EXPORT_LIST = re.compile(r"(?m)^[ \t]*export\s*\{([^}]+)\}\s*(?:;|$)")
_EXPORT_BINDING = re.compile(r"(?m)^[ \t]*export\s+(?:const|let|var)\s+(\w+)\b")
_MAX_MOUNT_DEPTH = 6
_TYPESCRIPT_SOURCE = {".js": (".ts", ".tsx"), ".mjs": (".mts",), ".cjs": (".cts",)}
_Key = tuple[int, str]
_Router = tuple[Path, _Key]


@dataclass(slots=True)
class _Module:
    text: str
    code: str
    blocks: scan.Blocks
    bindings: dict[_Key, tuple[int, bool]]
    exports: dict[str, _Key]


@dataclass(slots=True)
class _Mount:
    router: _Router
    prefix: str
    before: list[tuple[str, str]]
    middleware: list[str]
    registration: str


def _callback_span(code: str, start: int, end: int) -> tuple[int, int] | None:
    if not _CALLBACK.match(code, start, end):
        return None
    head = code[start:end]
    if re.match(r"(?:async\s+)?function\b", head):
        params = code.find("(", start, end)
        stop = scan.close_of(code, params)
        if stop < 0:
            return None
        body = re.match(r"\s*\{", code[stop + 1:end])
        opening = stop + body.end() if body else -1
    else:
        params = code.find("(", start, end) if "(" in head[:head.find("=>")] else -1
        after = scan.close_of(code, params) + 1 if params >= 0 else start
        arrow = re.match(r"\s*(?:async\s+)?(?:\w+\s*)?(?:\s*:\s*[\w.<>]+\s*)?=>\s*", code[after:end])
        if not arrow:
            return None
        opening = after + arrow.end()
        if opening < end and code[opening] != "{":
            return start, end - 1
    closing = scan.close_of(code, opening)
    if opening >= 0 and opening < closing < end:
        return start, closing
    return None


def _named_handlers(code: str, blocks: scan.Blocks):
    results = defaultdict(list)
    for match in _FUNCTION.finditer(code):
        if span := _callback_span(code, match.start(), len(code)):
            results[match[1]].append((blocks.at(match.start()), span))
    for match in _ARROW.finditer(code):
        # A block body is exact. Expression arrows are bounded by the line.
        end = code.find("\n", match.end())
        first = code[match.end():end if end >= 0 else len(code)]
        if "=>" in first and "{" in first.partition("=>")[2]:
            end = len(code)
        if span := _callback_span(code, match.end(), len(code) if end < 0 else end):
            results[match[1]].append((blocks.at(match.start()), span))
    return results


def _matching_prefix(prefix: str, path: str) -> bool:
    return prefix in {"", "/", "*"} or path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _callbacks(text: str, args: list[tuple[int, int]]) -> list[tuple[int, int]]:
    result = []
    for start, end in args:
        if text[start] == "[" and scan.close_of(text, start) == end - 1:
            result.extend(_callbacks(text, scan.split_args(text, start, end - 1)))
        else:
            result.append((start, end))
    return result


def _read_module(text: str) -> _Module | None:
    text = scan.mask(text, strings=False)
    factories = {a or b for a, b in _APP_IMPORT.findall(text)}
    router_factories = {f"{name}.Router" for name in factories}
    for imports in _ROUTER_IMPORT.findall(text):
        router_factories.update(alias or "Router" for alias in _ROUTER_NAME.findall(imports))
    if not factories and not router_factories:
        return None
    code = scan.mask(text)
    blocks = scan.Blocks(code)
    bindings = {}
    seen = set()
    for match in _BIND.finditer(code):
        name, callee = match.groups()
        key = (blocks.at(match.start()), name)
        if key in seen:
            bindings.pop(key, None)
        elif callee in factories or callee in router_factories:
            bindings[key] = (match.start(), callee in factories)
        seen.add(key)
    if not bindings:
        return None
    exports = {name: name for name in _EXPORT_BINDING.findall(code)}
    for name in _DEFAULT_EXPORT.findall(code):
        exports["default"] = name
    exports.update(_NAMED_EXPORT.findall(code))
    for clause in _EXPORT_LIST.findall(code):
        for item in clause.split(","):
            if names := re.fullmatch(r"\s*(\w+)(?:\s+as\s+(\w+))?\s*", item):
                exports[names[2] or names[1]] = names[1]
    return _Module(text, code, blocks, bindings, {
        exported: (-1, local) for exported, local in exports.items()
        if (-1, local) in bindings and not bindings[(-1, local)][1]
    })


def _imports(path: Path, module: _Module, modules: dict[Path, _Module]) -> dict[str, _Router]:
    imports = {}
    for spec, exported, alias in JavaScriptRules().local_imports(module.text):
        if not spec.startswith("."):
            continue
        base = (path.parent / spec).resolve()
        candidates = [base, *(base.with_suffix(suffix) for suffix in _TYPESCRIPT_SOURCE.get(base.suffix, ())),
                      *(base.parent / (base.name + suffix) for suffix in _SUFFIXES),
                      *(base / ("index" + suffix) for suffix in _SUFFIXES)]
        if target := next((item for item in candidates if item in modules), None):
            if key := modules[target].exports.get(exported):
                imports[alias] = (target, key)
    return imports


def _read_routes(root: Path, path: Path, module: _Module, imports: dict[str, _Router]):
    text, code, bindings, blocks = module.text, module.code, module.bindings, module.blocks
    lines = scan.Lines(text)
    handlers = _named_handlers(code, blocks)
    upstream = defaultdict(list)
    local = defaultdict(list)
    mounts = defaultdict(list)
    for match in _CALL.finditer(code):
        name, operation = match.groups()
        scope, offset = blocks.at(match.start()), match.start()
        key = (scope, name)
        if key not in bindings or bindings[key][0] >= offset:
            continue
        opening = match.end() - 1
        closing = scan.close_of(text, opening)
        if closing < 0 or not (args := scan.split_args(text, opening, closing)):
            continue
        route_path = scan.string_value(text[slice(*args[0])])
        if route_path is None and operation != "use":
            continue
        callbacks = _callbacks(text, args if route_path is None else args[1:])
        if not callbacks:
            continue
        before = [mid for prefix, mid in upstream[key] if _matching_prefix(prefix, route_path or "/")]
        start, end = callbacks[-1]
        handler = text[start:end]
        child = (scope, handler)
        local_child = bindings.get(child)
        mounted = (path, child) if local_child and not local_child[1] else imports.get(handler)
        if operation == "use" and mounted:
            mounts[key].append(_Mount(mounted, route_path or "/", list(upstream[key]),
                                      [scan.short(text[s:e]) for s, e in callbacks[:-1]],
                                      f"{path.relative_to(root).as_posix()}:{lines.at(offset)}"))
            continue
        span = _callback_span(code, start, end)
        # use(path, inline callback) can be the actual request entry point (e.g. SSR).
        if operation == "use" and (route_path is None or span is None):
            upstream[key].extend((route_path or "/", scan.short(text[s:e])) for s, e in callbacks)
            continue
        if not span and scan.is_name(handler):
            candidates = [s for owner, s in handlers[handler] if owner in {-1, scope}]
            span = candidates[0] if len(candidates) == 1 else None
        if not span:
            continue
        middleware = [*before, *(scan.short(text[s:e]) for s, e in callbacks[:-1])]
        local[key].append(Route(
            file_path=scan.posix(path), class_name=None,
            method=handler if scan.is_name(handler) else "inline handler",
            line=lines.at(span[0]), end_line=lines.at(span[1]),
            path=route_path, http_methods="ANY" if operation in {"all", "use"} else operation.upper(),
            language="javascript", declared_by=f"Express {name}.{operation}",
            middleware=middleware, registration=f"{path.relative_to(root).as_posix()}:{lines.at(offset)}",
        ))
    return local, mounts


def _mounted_routes(router: _Router, parsed, ancestry: tuple[_Router, ...] = ()):
    if router in ancestry or len(ancestry) > _MAX_MOUNT_DEPTH:
        return
    module, key = router
    routes, mounts = parsed[module]
    yield from routes.get(key, ())
    for mount in mounts.get(key, ()):
        for route in _mounted_routes(mount.router, parsed, (*ancestry, router)):
            path = scan.join_path(mount.prefix, route.path or "")
            before = [guard for prefix, guard in mount.before if _matching_prefix(prefix, path)]
            yield replace(route, path=path, middleware=[*before, *mount.middleware, *route.middleware],
                          mounts=[mount.registration, *route.mounts])


def discover(root: Path, limit: int) -> tuple[list[Route], int]:
    root = root.resolve()
    modules = {}
    scanned = 0
    for path in scan.walk(root, _SUFFIXES):
        if scanned >= limit:
            break
        if is_test(path):
            continue
        scanned += 1
        if (text := scan.read(path)) and "express" in text and (module := _read_module(text)):
            modules[path] = module
    parsed = {path: _read_routes(root, path, module, _imports(path, module, modules))
              for path, module in modules.items()}
    found = [route for path, module in modules.items() for key, (_, app) in module.bindings.items()
             if app for route in _mounted_routes((path, key), parsed)]
    return found, scanned
