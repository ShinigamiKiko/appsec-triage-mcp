"""Framework facts detected from the current checkout, never from adjacent projects."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FrameworkContext:
    root: Path
    language: str
    framework: str
    orm: str = "not detected"
    admin: str = "not detected"
    routing: str = "not detected"
    authorization: str = "not detected"
    templates: str = "not detected"
    repositories: list[str] = field(default_factory=list)
    base_classes: list[str] = field(default_factory=list)

    def render(self) -> str:
        orm_label = "Data access tools" if self.language == "Go" else "ORM"
        lines = [
            f"Repository: {self.root.name}",
            f"Language: {self.language}",
            f"Framework: {self.framework}",
            f"{orm_label}: {self.orm}",
            f"Admin: {self.admin}",
            f"Routing: {self.routing}",
            f"Authorization: {self.authorization}",
            f"Templates: {self.templates}",
        ]
        if self.repositories:
            lines.append("Repositories: " + ", ".join(self.repositories))
        if self.base_classes:
            lines.append("Framework base classes: " + ", ".join(self.base_classes))
        return "\n".join(lines)


def _manifest(root: Path, names: tuple[str, ...]) -> str:
    for name in names:
        path = root / name
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    return ""


def _php_routing(root: Path) -> str:
    parts = []
    for path in list((root / "src").rglob("*.php"))[:300] if (root / "src").is_dir() else []:
        try:
            if "#[Route" in path.read_text(encoding="utf-8", errors="replace"):
                parts.append("attributes")
                break
        except OSError:
            continue
    if (root / "config/routes.yaml").is_file() or (root / "config/routes").is_dir():
        parts.append("YAML")
    return " + ".join(parts) if parts else "not detected"


def _php_context(root: Path, composer: str) -> FrameworkContext | None:
    laravel = "laravel/framework" in composer or "laravel/lumen-framework" in composer
    # Doctrine is an ORM, not a Symfony marker. Standalone Doctrine projects
    # must keep their own routing and authorization conventions.
    symfony = "symfony/framework-bundle" in composer or (
        "symfony/http-kernel" in composer and (root / "config").is_dir()
    )
    if not laravel and not symfony:
        return None
    context = FrameworkContext(
        root=root,
        language="PHP",
        framework="Laravel" if laravel else "Symfony",
        orm="Eloquent" if laravel else "Doctrine",
        admin="EasyAdmin" if "easycorp/easyadmin-bundle" in composer else "not detected",
        routing=_php_routing(root),
        authorization="security.yaml + voters" if (root / "config/packages/security.yaml").is_file()
        or list((root / "src").rglob("*Voter.php")) else "not detected",
        templates="Blade" if laravel else "Twig",
    )
    repositories = list((root / "src").rglob("*Repository.php")) if (root / "src").is_dir() else []
    context.repositories = [path.relative_to(root).as_posix() for path in repositories[:8]]
    bases = []
    for path in list((root / "src").rglob("*Controller.php"))[:300] if (root / "src").is_dir() else []:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "AbstractCrudController" in text or "AbstractDashboardController" in text:
            bases.append(path.relative_to(root).as_posix())
            if len(bases) >= 8:
                break
    context.base_classes = bases
    return context


def _js_context(root: Path) -> FrameworkContext | None:
    try:
        manifest = json.loads(_manifest(root, ("package.json",)) or "{}")
    except ValueError:
        return None
    if not isinstance(manifest, dict):
        return None
    dependencies = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = manifest.get(section)
        if isinstance(entries, dict):
            dependencies.update(entries)
    frontends = ", ".join(name for package, name in (("vue", "Vue"), ("react", "React"))
                          if package in dependencies)
    for package, name, routing in (
        ("@nestjs/core", "NestJS", "controller decorators, module prefixes and guards"),
        ("next", "Next.js", "file-based routes and server actions"),
        ("fastify", "Fastify", "route declarations, hooks and plugin prefixes"),
        ("express", "Express", "app/router"),
        ("koa", "Koa", "middleware and router registrations"),
        ("@hapi/hapi", "Hapi", "server.route and route authentication"),
        ("hapi", "Hapi", "server.route and route authentication"),
    ):
        if package in dependencies:
            return FrameworkContext(root, "JavaScript/TypeScript", name, routing=routing,
                                    templates=frontends or "detect from render calls")
    if frontends:
        return FrameworkContext(root, "JavaScript/TypeScript", frontends,
                                routing="check browser and server entrypoints", templates=frontends)
    return None


def _go_context(root: Path) -> FrameworkContext | None:
    go = _manifest(root, ("go.mod",))
    if not go:
        return None
    data_tools = [name for marker, name in (
        ("gorm.io/gorm", "GORM"), ("github.com/jmoiron/sqlx", "sqlx"), ("entgo.io/ent", "ent"),
    ) if marker in go]
    if any((root / name).is_file() for name in ("sqlc.yaml", "sqlc.yml", "sqlc.json")):
        data_tools.append("sqlc")
    framework, routing = "Go standard library / custom router", "net/http or router resolved from source"
    for marker, name in (
        ("github.com/gofiber/fiber", "Fiber"),
        ("github.com/gin-gonic/gin", "Gin"),
        ("github.com/go-chi/chi", "chi"),
        ("github.com/labstack/echo", "Echo"),
        ("github.com/gorilla/mux", "gorilla/mux"),
        ("google.golang.org/grpc", "gRPC"),
    ):
        if marker in go:
            framework, routing = name, f"{name} registrations"
            break
    return FrameworkContext(root, "Go", framework, orm=", ".join(data_tools) or "not detected",
                            routing=routing, authorization="middleware and interceptors from source")


def _simple_context(root: Path) -> FrameworkContext | None:
    python = _manifest(root, ("requirements.txt", "pyproject.toml"))
    if "django" in python.lower():
        return FrameworkContext(root, "Python", "Django", orm="Django ORM", routing="urls.py",
                                templates="Django templates")
    java = _manifest(root, ("pom.xml", "build.gradle", "build.gradle.kts"))
    if "spring-boot" in java or "spring-webmvc" in java:
        return FrameworkContext(root, "Java/Kotlin", "Spring MVC", routing="annotations",
                                templates="detect from view resolver")
    return None


def detect(roots: list[Path]) -> list[FrameworkContext]:
    contexts = []
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        composer = _manifest(root, ("composer.json", "composer.lock"))
        if context := _php_context(root, composer):
            contexts.append(context)
            continue
        server_contexts = [context for context in (_js_context(root), _go_context(root)) if context]
        if server_contexts:
            contexts.extend(server_contexts)
        elif context := _simple_context(root):
            contexts.append(context)
    return contexts


def render(roots: list[Path]) -> str:
    contexts = detect(roots)
    if not contexts:
        return ""
    return "## Current repository framework context\n\n" + "\n\n".join(
        context.render() for context in contexts
    )
