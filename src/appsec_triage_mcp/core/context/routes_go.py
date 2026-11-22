"""HTTP registrations for Fiber and net/http, including local wiring helpers."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..testpaths import is_test
from . import routes_scan as scan
from .routes import Route

_FUNCTION = re.compile(r"(?m)^[ \t]*func\s+(?:\(\s*(\w+)\s+\*?(\w+)\s*\)\s*)?(\w+)\s*\(")
_BODY = re.compile(r"\s*(?:(?:\([^{}\n]*\)|[\w.*\[\]]+)\s*)?\{")
_PARAMETER = re.compile(r"(\w+)\s+(\.\.\.)?\*?([\w.]+)")
_CALL = re.compile(r"(?m)^[ \t]*(?:return[ \t]+|(?:(\w+)\s*:?=\s*)?)([\w.]+)\s*\(")
_LOCAL_TYPE = re.compile(
    r"(?m)^[ \t]*(\w+)[ \t]*:=[ \t]*(?:&?([\w.]+)\s*\{|new\s*\(\s*([\w.]+)\s*\))"
    r"|^[ \t]*var[ \t]+(\w+)[ \t]+\*?([\w.]+)\b"
)
_RETURN_ADAPTER = re.compile(r"\breturn[ \t]+([\w.]+)\s*\(")
_IMPORT_SECTION = re.compile(r'(?m)^import[ \t]*(?:\(([^)]*)\)|([^\n]+))')
_IMPORT = re.compile(r'(?m)^\s*(?:(\w+)\s+)?"([^"\n]+)"')
_CONST_BLOCK = re.compile(r"(?ms)^const\s*\((.*?)^\)")
_CONSTANT = re.compile(r'(?m)^\s*(?:const\s+)?(\w+)\s*=\s*("[^"\n]*"|`[^`\n]*`)\s*$')
_VERBS = {"Get", "Post", "Put", "Patch", "Delete", "Head", "Options", "All"}
_FIBER = {"github.com/gofiber/fiber", "github.com/gofiber/fiber/v2", "github.com/gofiber/fiber/v3"}
_HTTP_SERVERS = {"ListenAndServe", "ListenAndServeTLS"}


@dataclass(slots=True)
class _File:
    path: Path
    relative: str
    package: str
    text: str
    code: str
    imports: dict[str, str]
    constants: dict[str, str | None]
    lines: scan.Lines
    blocks: scan.Blocks


@dataclass(slots=True)
class _Function:
    file: _File
    name: str
    receiver: str
    start: int
    body: int
    end: int
    result: str
    params: list[tuple[str, bool, str]]
    locals: list[tuple[int, str, str]]
    calls: list[tuple[int, str, str, list[tuple[int, int]]]]


@dataclass(slots=True)
class _Ref:
    func: _Function
    start: int
    end: int

    @property
    def text(self) -> str:
        return self.func.file.text[self.start:self.end]


@dataclass(slots=True)
class _Router:
    library: str
    prefix: str = ""
    middleware: list[tuple[str, str]] = field(default_factory=list)
    servers: list[tuple[list[str], str]] = field(default_factory=list)

    def before(self, path: str) -> list[str]:
        # Fiber's string middleware paths are prefix matches.
        return [name for prefix, name in self.middleware if path.startswith(prefix)]


def _imports(text: str) -> dict[str, str]:
    imports = {}
    for block, single in _IMPORT_SECTION.findall(text):
        for alias, name in _IMPORT.findall(block or single):
            bits = name.split("/")
            default = bits[-2] if len(bits) > 1 and re.fullmatch(r"v\d+", bits[-1]) else bits[-1]
            imports[alias or default] = name
    return imports


def _read_functions(file: _File) -> list[_Function]:
    found = []
    for match in _FUNCTION.finditer(file.code):
        stop = scan.close_of(file.code, match.end() - 1)
        if stop < 0 or not (body := _BODY.match(file.code, stop + 1)):
            continue
        opening = body.end() - 1
        closing = scan.close_of(file.code, opening)
        if closing < 0:
            continue
        params = []
        for start, end in scan.split_args(file.code, match.end() - 1, stop):
            part = _PARAMETER.fullmatch(file.code[start:end])
            if part is None:
                params.clear()
                break
            params.append((part[1], bool(part[2]), part[3]))
        calls = []
        for expression in _CALL.finditer(file.code, opening + 1, closing):
            start = expression.start()
            if file.blocks.at(start) != opening:
                continue
            end = scan.close_of(file.text, expression.end() - 1)
            if 0 <= end < closing:
                calls.append((start, expression[1] or "", expression[2],
                              scan.split_args(file.text, expression.end() - 1, end)))
        if match[1]:
            params.append((match[1], False, match[2]))
        locals_ = [(m.start(), m[1] or m[4], m[2] or m[3] or m[5])
                   for m in _LOCAL_TYPE.finditer(file.code, opening + 1, closing)
                   if file.blocks.at(m.start()) == opening]
        result = file.code[stop + 1:opening].strip()
        found.append(_Function(file, match[3], match[2] or "", match.start(), opening, closing,
                               result, params, locals_, calls))
    return found


def _qualified(file: _File, name: str) -> tuple[str, str]:
    prefix, dot, member = name.partition(".")
    if not dot:
        return file.package, prefix
    return file.imports.get(prefix, ""), member


def _receiver_type(ref: _Ref, receiver: str, functions) -> tuple[str, str] | None:
    fn = ref.func
    types = {name: type_ for name, _, type_ in fn.params}
    types.update((name, type_) for offset, name, type_ in fn.locals if offset < ref.start)
    if receiver in types:
        return _qualified(fn.file, types[receiver])
    assigned = next((callee for offset, name, callee, _ in reversed(fn.calls)
                     if offset < ref.start and name == receiver), "")
    package, name = _qualified(fn.file, assigned)
    declarations = functions.get((package, "", name), ())
    if len(declarations) != 1:
        return None
    constructor = declarations[0]
    if not re.fullmatch(r"\*?\w+(?:\.\w+)?", constructor.result):
        return None
    return _qualified(constructor.file, constructor.result.lstrip("*"))


def _function_for(ref: _Ref, name: str, functions) -> _Function | None:
    if not scan.is_name(name):
        return None
    file = ref.func.file
    parts = scan.name_parts(name)
    if len(parts) == 1:
        key = (file.package, "", parts[0])
    elif len(parts) == 2 and parts[0] in file.imports:
        key = (file.imports[parts[0]], "", parts[1])
    elif len(parts) == 2 and (type_ := _receiver_type(ref, parts[0], functions)):
        package, receiver = type_
        key = (package, receiver, parts[1])
    else:
        return None
    candidates = functions.get(key, [])
    return candidates[0] if len(candidates) == 1 else None


def _resolve_handler(ref: _Ref, functions) -> tuple[_Function, str, int, int] | None:
    file = ref.func.file
    if re.match(r"func\s*\(", ref.text):
        params_end = scan.close_of(file.code, file.code.find("(", ref.start, ref.end))
        if params_end >= 0 and (body := _BODY.match(file.code, params_end + 1, ref.end)):
            end = scan.close_of(file.code, body.end() - 1)
            if 0 <= end < ref.end:
                return ref.func, "inline handler", ref.start, end
        return None
    if not (fn := _function_for(ref, ref.text, functions)):
        return None
    name = f"{fn.receiver}.{fn.name}" if fn.receiver else fn.name
    return fn, name, fn.start, fn.end


def _forwards_http_handler(wrapper: _Function, functions) -> bool:
    if len(wrapper.params) != 1:
        return False
    param, _, type_ = wrapper.params[0]
    if _qualified(wrapper.file, type_) != ("net/http", "Handler"):
        return False
    file = wrapper.file
    for candidate in _RETURN_ADAPTER.finditer(file.code, wrapper.body + 1, wrapper.end):
        if file.blocks.at(candidate.start()) != wrapper.body:
            continue
        if _qualified(file, candidate[1]) != ("net/http", "HandlerFunc"):
            continue
        opening = candidate.end() - 1
        closing = scan.close_of(file.text, opening)
        if not (0 <= closing < wrapper.end):
            continue
        args = scan.split_args(file.text, opening, closing)
        if len(args) != 1:
            continue
        ref = _Ref(wrapper, *args[0])
        if scan.is_name(ref.text) and scan.name_parts(ref.text) == [param, "ServeHTTP"]:
            return True
        if not (callback := _resolve_handler(ref, functions)):
            continue
        _, _, start, end = callback
        if callback[1] == "inline handler" and re.search(rf"\b{re.escape(param)}\.ServeHTTP\s*\(", file.code[start:end]):
            return True
    return False


def _unwrap_http(ref: _Ref, functions) -> tuple[_Ref, list[str]]:
    middleware = []
    for _ in range(6):
        file = ref.func.file
        call = scan.as_call(file.text, ref.start, ref.end)
        if not call or len(call[1]) != 1:
            break
        name, args = call
        if _qualified(file, name) != ("net/http", "HandlerFunc"):
            wrapper = _function_for(ref, name, functions)
            if not wrapper or not _forwards_http_handler(wrapper, functions):
                break
            middleware.append(name)
        ref = _Ref(ref.func, *args[0])
    return ref, middleware


def _value(file: _File, ref: _Ref) -> str | None:
    literal = scan.string_value(ref.text)
    return literal if literal is not None else file.constants.get(ref.text)


def _expanded(refs: list[_Ref], bound: dict[str, list[_Ref]]) -> list[_Ref]:
    return [value for ref in refs for value in bound.get(ref.text.removesuffix("..."), [ref])]


def _register(fn: _Function, offset: int, name: str, router: _Router, args: list[_Ref],
              bound: dict[str, list[_Ref]], functions, found: list[tuple[_Router, Route]]) -> None:
    path = _value(fn.file, args[0]) if args else None
    handlers = _expanded(args[1:], bound)
    if path is None or not handlers:
        return
    ref, wrappers = _unwrap_http(handlers[-1], functions) if router.library == "net/http" else (handlers[-1], [])
    if not (handler := _resolve_handler(ref, functions)):
        return
    target, method, start, end = handler
    verb = name.upper() if name in _VERBS and name != "All" else "ANY"
    if router.library == "net/http":
        first, space, remainder = path.partition(" ")
        if space and first.isalpha() and first.isupper():
            verb, path = first, remainder.strip()
    full_path = scan.join_path(router.prefix, path)
    found.append((router, Route(
        file_path=scan.posix(target.file.path), class_name=None, method=method,
        line=target.file.lines.at(start), end_line=target.file.lines.at(end),
        path=full_path, http_methods=verb, language="go",
        declared_by=f"{'net/http' if router.library == 'net/http' else 'Fiber'} {name}",
        middleware=[*router.before(full_path), *(scan.short(item.text) for item in handlers[:-1]), *wrappers],
        registration=f"{fn.file.relative}:{fn.file.lines.at(offset)}",
    )))


def _serve(fn: _Function, offset: int, refs: list[_Ref], routers: dict[str, _Router], functions) -> None:
    if not refs:
        return
    ref, wrappers = _unwrap_http(refs[-1], functions)
    owner = "@net/http-default" if ref.text == "nil" else ref.text
    if (router := routers.get(owner)) and router.library == "net/http":
        entry = (wrappers, f"{fn.file.relative}:{fn.file.lines.at(offset)}")
        if entry not in router.servers:
            router.servers.append(entry)


def _walk_function(fn: _Function, routers: dict[str, _Router], bound: dict[str, list[_Ref]],
                   functions, found: list[tuple[_Router, Route]], depth: int) -> None:
    for offset, assignment, callee, spans in fn.calls:
        refs = [_Ref(fn, *span) for span in spans]
        package, name = _qualified(fn.file, callee)
        owner, _, member = callee.partition(".")
        router = routers.get(owner)
        if assignment and ((package in _FIBER and name == "New") or (package, name) == ("net/http", "NewServeMux")):
            routers[assignment] = _Router(package)
        elif router and router.library in _FIBER and member in {"Use", "Group"}:
            path = _value(fn.file, refs[0]) if refs else None
            middleware = [scan.short(ref.text) for ref in _expanded(refs[1:] if path is not None else refs, bound)]
            prefix = router.prefix if path is None else scan.join_path(router.prefix, path)
            if member == "Group" and assignment and path is not None:
                routers[assignment] = _Router(router.library, prefix, [
                    *router.middleware, *((prefix, item) for item in middleware),
                ])
            elif member == "Use":
                router.middleware.extend((prefix, item) for item in middleware)
        elif router and ((router.library in _FIBER and member in _VERBS)
                         or (router.library == "net/http" and member in {"HandleFunc", "Handle"})):
            _register(fn, offset, member, router, refs, bound, functions, found)
        elif package == "net/http" and name in {"HandleFunc", "Handle"}:
            default = routers.setdefault("@net/http-default", _Router(package))
            _register(fn, offset, name, default, refs, bound, functions, found)
        elif package == "net/http" and name in _HTTP_SERVERS:
            _serve(fn, offset, refs, routers, functions)
        elif package == "log" and name in {"Fatal", "Panic"} and len(refs) == 1:
            ref = refs[0]
            if call := scan.as_call(fn.file.text, ref.start, ref.end):
                serve_package, serve_name = _qualified(fn.file, call[0])
                if serve_package == "net/http" and serve_name in _HTTP_SERVERS:
                    _serve(fn, offset, [_Ref(fn, *span) for span in call[1]], routers, functions)
        elif depth and not assignment and (targets := functions.get((package, "", name))) and len(targets) == 1:
            child = targets[0]
            child_routers = {param: routers[ref.text] for (param, _, _), ref in zip(child.params, refs)
                             if ref.text in routers}
            if not child_routers:
                continue
            child_args = {param: _expanded(refs[pos:] if variadic else refs[pos:pos + 1], bound)
                          for pos, (param, variadic, _) in enumerate(child.params)}
            _walk_function(child, child_routers, child_args, functions, found, depth - 1)


def discover(root: Path, limit: int) -> tuple[list[Route], int]:
    module = re.search(r"(?m)^module\s+(\S+)", scan.read(root / "go.mod") or "")
    base = module[1] if module else ""
    functions = defaultdict(list)
    constants = defaultdict(dict)
    scanned = 0
    for path in scan.walk(root, (".go",)):
        if scanned >= limit:
            break
        if is_test(path):
            continue
        scanned += 1
        raw = scan.read(path)
        if not raw:
            continue
        text = scan.mask(raw, strings=False)
        code = scan.mask(text)
        package = f"{base}/{path.parent.relative_to(root).as_posix().strip('.')}".strip("/")
        constants[package].update((key, scan.string_value(value)) for key, value in _CONSTANT.findall(text)
                                  if re.search(rf"(?m)^const[ \t]+{re.escape(key)}\b", text))
        for block in _CONST_BLOCK.findall(text):
            constants[package].update((key, scan.string_value(value)) for key, value in _CONSTANT.findall(block))
        file = _File(path, path.relative_to(root).as_posix(), package, text, code, _imports(text),
                     constants[package], scan.Lines(text), scan.Blocks(code))
        for fn in _read_functions(file):
            functions[(package, fn.receiver, fn.name)].append(fn)
    registered = []
    for definitions in functions.values():
        for fn in definitions:
            _walk_function(fn, {}, {}, functions, registered, depth=2)
    routes = []
    for router, route in registered:
        if router.servers:
            routes.extend(replace(route, middleware=[*middleware, *route.middleware], mounts=[location])
                          for middleware, location in router.servers)
        else:
            routes.append(route)
    return routes, scanned
