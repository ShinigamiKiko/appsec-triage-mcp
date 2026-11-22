"""Read HTTP route declarations and their handlers from project source."""

from __future__ import annotations

import hashlib
import os
import re
from bisect import bisect_left
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from .context import routes
from .context.evidence import MAX_FILE_BYTES, SEARCH_FILES, _tool_output

_SKIP = {"vendor", "node_modules", "dist", "build", "target", "var", "cache", "out", "coverage",
         "venv", "__pycache__", "keys", "secrets"}
_TEST_DIRS = {"test", "tests", "__tests__", "fixtures", "examples"}
_EXTENSIONS = {".php", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt"}
_TEST_SUFFIXES = ("_test.py", "_test.go", ".test.js", ".spec.js", ".test.ts", ".spec.ts",
                  ".test.tsx", ".spec.tsx", "test.php", "test.java", "test.kt")
_VERBS = r"GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
_STRING = r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
_PHP_ROUTE = re.compile(
    r"^[ \t]*(?P<annotation>/\*\*\s*|\*\s*)?@(?:[\w\\]+\\)?Route\s*\("
    r"|^[ \t]*#\[\s*(?:[\w\\]+\\)?Route\s*\(", re.MULTILINE)
_PHP_ARGS = re.compile(rf"(?P<args>(?:{_STRING}|[^()'\"\n]|\n|\((?:{_STRING}|[^()'\"])*\))*)\)")
_PHP_NAMESPACE = re.compile(r"^\s*namespace\s+([\w\\]+)", re.MULTILINE)
_PHP_SUBCLASS = re.compile(r"^[ \t]*(?P<mod>(?:(?:abstract|final|readonly)\s+)*)class\s+(\w+)"
                           r"\s+extends\s+([\w\\]+)", re.MULTILINE)
_PHP_IMPORT = re.compile(r"^[ \t]*use\s+([\w\\]+)(?:\s+as\s+(\w+))?\s*;", re.MULTILINE)
_EASYADMIN_CRUD = r"EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController"
_PHP_METHODS = re.compile(r"\bmethods\s*[:=]\s*(\[[^\]]*\]|\{[^}]*\}|['\"][^'\"]+['\"])")
_HTTP_VERB = re.compile(rf"\b(?:METHOD_)?({_VERBS})\b", re.IGNORECASE)

_PY_ROUTE = re.compile(r"^\s*@(?:\w+\.)?(?P<verb>get|post|put|patch|delete|head|options|route)"
                       r"""\s*\(\s*['"](?P<path>[^'"]+)""", re.IGNORECASE)
_JS_ROUTE = re.compile(r"^\s*(?:app|router|route|api)\.(?P<verb>get|post|put|patch|delete|head|options|all)"
                       r"""\s*\(\s*['"](?P<path>[^'"]+)""", re.IGNORECASE)
_JAVA_ROUTE = re.compile(r"^\s*@(?P<verb>Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*"
                         r"""(?:(?:value|path)\s*=\s*)?['"](?P<path>[^'"]+)""")
_GO_ROUTE = re.compile(rf"^\s*(?:(?P<receiver>[\w.]+)\.)?(?P<verb>HandleFunc|Handle|{_VERBS})"
                       rf"\s*\(\s*(?P<path>\"[^\"]+\"|[A-Za-z_]\w*)", re.IGNORECASE)
_GO_CONSTANT = re.compile(r"^\s*(?:const\s+)?(?:\w+\s+)?(?P<name>\w+)\s*=\s*\"(?P<value>/[^\"]*)\"",
                          re.MULTILINE)
_GO_GROUP = re.compile(r"^\s*(?P<var>\w+)\s*:=\s*\w+\.Group\((?P<path>[A-Za-z_]\w*|\"[^\"]+\")",
                       re.MULTILINE)
_GO_NON_ROUTE_RECEIVERS = {"ctx", "context", "req", "request", "c", "client", "httpclient"}
_PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")
_CALLBACK = re.compile(r"""['"]\s*,\s*([\w.]+)\s*[,)]""")
_GO_CALLBACK = re.compile(r"^\s*,\s*([\w.]+)\s*[,)]")
_LANG_ROUTES = {".py": _PY_ROUTE, ".go": _GO_ROUTE, ".java": _JAVA_ROUTE, ".kt": _JAVA_ROUTE,
                **dict.fromkeys((".js", ".jsx", ".ts", ".tsx", ".cjs", ".mjs"), _JS_ROUTE)}


@dataclass(slots=True)
class Endpoint:
    file_path: str
    line: int
    end_line: int
    method: str
    path: str
    handler: str
    declared_by: str

    @property
    def finding_id(self) -> str:
        identity = f"{self.file_path}:{self.line}:{self.method}:{self.path}:{self.handler}"
        return "idor:" + hashlib.sha256(identity.encode()).hexdigest()[:20]

    def as_dict(self) -> dict:
        return {**asdict(self), "finding_id": self.finding_id}


@dataclass(slots=True)
class EndpointInventory:
    endpoints: list[Endpoint] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0


def _route_yaml(path: Path) -> bool:
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return False
    return ((path.stem == "routes" and path.parent.name == "config")
            or any(p.name == "routes" and p.parent.name == "config" for p in path.parents))


def _package_config(path: Path) -> bool:
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return False
    return any(folder.name == "packages" and folder.parent.name == "config"
               for folder in (path.parent, path.parent.parent))


def _files(root: Path, include_tests: bool, include_package_config: bool):
    for directory, dirs, names in os.walk(root):
        parent = Path(directory)
        package_envs = include_package_config and (parent.name, parent.parent.name) == ("packages", "config")
        dirs[:] = sorted(d for d in dirs if not (
            d.startswith(".") or d.lower() in _SKIP or _tool_output(d.lower())
            or not include_tests and d.lower() in _TEST_DIRS and not (package_envs and d == "test")
            or (Path(directory) / d).is_symlink()))
        if not include_tests and parent.name == "test" and parent.parent.name == "packages":
            dirs.clear()
        for name in sorted(names):
            path = Path(directory) / name
            package_config = include_package_config and _package_config(path.relative_to(root))
            if not include_tests and parent.name == "test" and not package_config:
                continue
            if name.startswith(".") or not include_tests and (
                name.startswith("test_") or name.lower().endswith(_TEST_SUFFIXES)
            ):
                continue
            if (path.suffix.lower() in _EXTENSIONS or _route_yaml(path.relative_to(root)) or package_config) and (
                not path.is_symlink() and path.is_file()
            ):
                yield path


def _php_routes(path: Path, text: str, handlers: dict[str, tuple], subclasses: dict, add: Callable) -> None:
    lines = text.splitlines()
    cls = next(((i, m[1]) for i, line in enumerate(lines, 1) if (m := routes._CLASS_DEF.match(line))), None)
    if cls is None:
        return
    namespace = _PHP_NAMESPACE.search(text)
    fqcn = (namespace[1] + "\\" if namespace else "") + cls[1]
    if subclass := _PHP_SUBCLASS.search(text):
        parent = subclass[3]
        if not parent.startswith("\\"):
            imports = {alias or name.rsplit("\\", 1)[-1]: name.lstrip("\\")
                       for name, alias in _PHP_IMPORT.findall(text)}
            first, sep, rest = parent.partition("\\")
            parent = imports.get(first, (namespace[1] + "\\" if namespace else "") + first) + sep + rest
        subclasses[fqcn] = (parent.lstrip("\\"), "abstract" in subclass["mod"], str(path), cls[0], len(lines))
    spans = routes._method_spans(lines)
    for start, end, method in spans:
        handlers[f"{fqcn}::{method}"] = (str(path), start, end)
    if not spans or "Route" not in text:
        return
    newlines = [m.start() for m in re.finditer("\n", text)]
    prefixes = []
    class_methods = ""
    for marker in _PHP_ROUTE.finditer(text):
        args = _PHP_ARGS.match(text, marker.end())
        if not args:
            continue
        arg_text = re.sub(r"\n[ \t]*\*[ \t]*", " ", args["args"]).strip()
        path_match = routes._PATH_NAMED.search(arg_text) or routes._PATH_POSITIONAL.match(arg_text)
        if not path_match:
            continue
        route_path = path_match[1]
        methods = _PHP_METHODS.search(arg_text)
        verbs = ",".join(_HTTP_VERB.findall(methods[1].upper())) if methods else ""
        line = bisect_left(newlines, marker.start()) + 1
        if line < cls[0]:
            prefixes.append(route_path)
            class_methods = verbs
            continue
        span = next((s for s in spans if s[0] >= line), None)
        if span is None:
            continue
        for prefix in prefixes or [""]:
            path_value = prefix.rstrip("/") + "/" + route_path.lstrip("/")
            add(Endpoint(str(path), span[0], span[1], verbs or class_methods or "ANY", path_value,
                         fqcn + "::" + span[2], "attribute" if "#[" in marker[0] else "annotation"))


def _yaml_routes(path: Path, text: str):
    # The source position also locates registrations whose controller uses a service alias.
    document = yaml.compose(text, Loader=yaml.SafeLoader)
    if not isinstance(document, yaml.MappingNode):
        return
    for _, entry in document.value:
        if not isinstance(entry, yaml.MappingNode):
            continue
        fields = {k.value: v for k, v in entry.value if isinstance(k, yaml.ScalarNode)}
        route_path = fields.get("path")
        controller = fields.get("controller")
        defaults = fields.get("defaults")
        if not controller and isinstance(defaults, yaml.MappingNode):
            controller = next((v for k, v in defaults.value if k.value == "_controller"), None)
        if not isinstance(controller, yaml.ScalarNode) or not isinstance(route_path, yaml.ScalarNode):
            continue
        handler = controller.value.lstrip("\\")
        if "::" not in handler and "\\" in handler:
            handler += "::__invoke"
        methods = fields.get("methods")
        if isinstance(methods, yaml.SequenceNode):
            verbs = ",".join(item.value.upper() for item in methods.value if isinstance(item, yaml.ScalarNode))
        elif isinstance(methods, yaml.ScalarNode):
            verbs = methods.value.upper()
        else:
            verbs = ""
        line = controller.start_mark.line + 1
        yield Endpoint(str(path), line, line, verbs or "ANY", route_path.value, handler, "yaml")


def _lexical_routes(path: Path, text: str, add: Callable):
    pattern = _LANG_ROUTES.get(path.suffix.lower())
    if pattern is None:
        return
    constants = {match["name"]: match["value"] for match in _GO_CONSTANT.finditer(text)} if path.suffix == ".go" else {}
    groups = {match["var"]: match["path"] for match in _GO_GROUP.finditer(text)} if path.suffix == ".go" else {}

    def resolve_go_path(raw):
        if raw.startswith('"'):
            return raw[1:-1]
        return constants.get(raw, "")

    lines = text.splitlines()
    for line_no, line in enumerate(lines, 1):
        match = pattern.search(line)
        if not match:
            continue
        if path.suffix == ".go" and (receiver := match.groupdict().get("receiver")) and receiver.lower() in _GO_NON_ROUTE_RECEIVERS:
            continue
        verb = match["verb"].upper()
        route_path = resolve_go_path(match["path"])
        if not route_path:
            continue
        if path.suffix == ".go" and (receiver := match.groupdict().get("receiver")) in groups:
            prefix = resolve_go_path(groups[receiver])
            route_path = prefix.rstrip("/") + "/" + route_path.lstrip("/")
        handler = "unresolved handler"
        if path.suffix == ".py":
            definition = next((m for item in lines[line_no:line_no + 12] if (m := _PY_DEF.match(item))), None)
            if definition:
                handler = definition[1]
        elif path.suffix == ".go" and (callback := _GO_CALLBACK.search(line[match.end("path"):])):
            handler = callback[1]
        elif callback := _CALLBACK.search(line[match.end("path"):]):
            handler = callback[1]
        if verb in {"ROUTE", "ALL", "HANDLE", "HANDLEFUNC", "REQUEST"}:
            verb = "ANY"
        add(Endpoint(str(path), line_no, min(len(lines), line_no + 120), verb, route_path, handler, "lexical"))


def discover(roots: list[Path], *, limit: int = 200, include_tests: bool = False,
             on_source: Callable[[Path, str], None] | None = None) -> EndpointInventory:
    inventory = EndpointInventory()
    seen_files = set()
    seen_endpoints = set()
    oversized = unreadable = omitted = generated_crud = unresolved_yaml = 0

    def add(endpoint):
        nonlocal omitted
        key = (endpoint.file_path, endpoint.line, endpoint.method, endpoint.path)
        if key in seen_endpoints:
            return
        seen_endpoints.add(key)
        if len(inventory.endpoints) < limit:
            inventory.endpoints.append(endpoint)
        else:
            omitted += 1

    for root in dict.fromkeys(Path(r).resolve() for r in roots):
        if not root.is_dir():
            inventory.warnings.append(f"source root is not a directory: {root}")
            continue
        handlers, subclasses, yaml_endpoints = {}, {}, []
        for path in _files(root, include_tests, include_package_config=on_source is not None):
            if path in seen_files:
                continue
            if len(seen_files) >= SEARCH_FILES:
                inventory.warnings.append(f"source file limit reached at {SEARCH_FILES}")
                break
            seen_files.add(path)
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    oversized += 1
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                unreadable += 1
                continue
            inventory.files_scanned += 1
            if path.suffix.lower() in {".yaml", ".yml"}:
                if on_source is not None and _package_config(path.relative_to(root)):
                    on_source(path, content)
                    continue
                try:
                    yaml_endpoints.extend(_yaml_routes(path, content))
                except (yaml.YAMLError, RecursionError):
                    inventory.warnings.append(f"could not parse route configuration: {path}")
                continue
            if on_source is not None:
                on_source(path, content)
            if path.suffix.lower() == ".php":
                _php_routes(path, content, handlers, subclasses, add)
            else:
                _lexical_routes(path, content, add)
        for endpoint in yaml_endpoints:
            if location := handlers.get(endpoint.handler):
                endpoint.file_path, endpoint.line, endpoint.end_line = location
            else:
                unresolved_yaml += 1
            add(endpoint)
        for name, (parent, abstract, path, line, end) in subclasses.items():
            if abstract:
                continue
            visited = {name}
            while parent in subclasses and parent not in visited:
                visited.add(parent)
                parent = subclasses[parent][0]
            if parent == _EASYADMIN_CRUD:
                generated_crud += 1
                add(Endpoint(path, line, end, "", "", name, "easyadmin_crud"))
    if oversized or unreadable:
        inventory.warnings.append(f"source files skipped: {oversized} over size limit, {unreadable} unreadable")
    if omitted:
        inventory.warnings.append(f"endpoint limit {limit}: {omitted} additional endpoints omitted")
    if unresolved_yaml:
        inventory.warnings.append(
            f"{unresolved_yaml} YAML routes point to an unresolved handler or service alias; "
            "source locations identify their registrations"
        )
    if generated_crud:
        inventory.warnings.append(
            f"{generated_crud} EasyAdmin CRUD controllers reviewed at class level; "
            "effective generated URLs and enabled actions depend on framework configuration"
        )
    if not inventory.endpoints:
        inventory.warnings.append("no HTTP route declarations recognized in the scanned files")
    return inventory
