# Разработка

Команды выполняются из корня репозитория. Нужен Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m ruff check src tests --no-cache
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider
```

В Windows проверки запускаются из PowerShell.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\scripts\check.ps1
```

`src/` содержит устанавливаемый Python-пакет. Тесты импортируют его после установки,
поэтому случайный импорт из корня проекта не скрывает ошибки упаковки.
Полная перенесённая библиотека находится в `src/appsec_triage_mcp/core/`;
её происхождение и изменения описаны в [vendoring.md](vendoring.md).
Промпты, конфиги и правила входят в wheel как package data.

Сборка wheel и Docker-образа:

```bash
.venv/bin/python -m pip wheel --no-deps --wheel-dir .local/dist .
docker build -t appsec-triage-mcp:local .
```

`build/` и `src/*.egg-info/` могут создаваться инструментами сборки; они не входят в Git.
`.venv/` — локальное окружение разработчика. `.local/` — настройки, ключи, результаты,
справочные отчёты и собранные артефакты. Эти каталоги не входят в Git или Docker context.
Сборочный Docker context ограничен `src/`, `Dockerfile`, `pyproject.toml`, `README.md`, `LICENSE`.

Проверка установленного пакета в контейнере:

```bash
docker run --rm --workdir /tmp --entrypoint python appsec-triage-mcp:local -c "from appsec_triage_mcp.assets import asset_index; print(len(asset_index('prompts')))"
```

После пересборки образа новая сессия Gateway получит изменения. Для изменения локального
профиля используйте `.venv/bin/python scripts/setup_docker_mcp.py --skip-build`. Сервер не запускает LLM;
новые инструменты должны сохранять выполнение анализа в подключённом MCP-клиенте.
