# Использование AppSec MCP

Все команды ниже выполняются из корня репозитория.

Самостоятельный MCP-сервер для Docker MCP Toolkit. **Сканеры, парсеры findings,
чтение кода, LSP, промпты и настройки** AppSec находятся внутри пакета MCP.
Собственного LLM-агента нет: анализ моделью выполняет подключённый MCP-клиент.
API-ключ, модель и URL LLM для сервера не нужны.

```text
appsec-scan-projects "URL1,URL2,URL3"
 → Docker MCP Gateway → MCP-сервер
 → git clone → сканеры AppSec → findings + HTML
 → удаление клона → HTML в локальной папке .local/reports
 → по запросу: Telegram / SCP
```

До трёх Git-проектов через запятую, отдельное задание и каталог для каждого.
При каждом запуске создаётся свежий shallow clone default-ветки. Сохранённой рабочей
копии для `git pull` нет. Экосистемы определяются по файлам каждого проекта;
`--ecosystems` переопределяет их явно.

## Установка и запуск

Основная инструкция охватывает Linux x86-64 с Docker Engine, плагином Docker MCP и Python 3.11+. Сначала включите профили Docker MCP, установите клиент и запустите установщик. [Установка на Linux](../README.md#установка) · [Вариант для Windows](../README.md#windows)

Установщик создаёт профиль `appsec-triage` и подключает каталог настроек `.local/config/` к контейнеру. Если образ уже собран, обновите профиль командой `.venv/bin/python scripts/setup_docker_mcp.py --skip-build`.

```bash
# Один проект
.venv/bin/appsec-scan-projects "https://git.example/team/project.git"

# До трёх проектов
.venv/bin/appsec-scan-projects "https://git.example/team/a.git,https://git.example/team/b.git,https://git.example/team/c.git"

# Интерактивный ввод ссылок
.venv/bin/appsec-scan-projects

# Конкретные инструменты и папка отчётов
.venv/bin/appsec-scan-projects "https://git.example/team/project.git" --scanners opengrep,wolfee --output ./reports
```

Скрипт является MCP-клиентом: сканирование идёт через Gateway, а не обходным вызовом агента.
Выход — `.local/reports/<project>-<job_id>.html` и JSON со статусом. HTML содержит статус каждого
сканера, версии, находки, severity, CWE, файлы/строки и доступные фрагменты кода.
Находки сканеров не выдаются за подтверждённые уязвимости. Неполный скан отмечается явно.
Код возврата клиента: `0` при успехе всех проектов/доставок, `1` при сбое.

Параметры: `--ecosystems npm,go`, `--timeout 7200`, `--cpus 3`, `--memory 8Gb`,
`--profile appsec-triage`, `--telegram`, `--scp default`.
Выбор сканеров по умолчанию взят из AppSec; `appsec_list_scanners` показывает доступность.
Dockerfile включает сканеры и LSP: Opengrep, CodeQL, Psalm, Wolfee, govulncheck,
Python LSP, gopls, TypeScript LSP и Phpactor. CodeQL в текущей сборке — для Go и JavaScript.

## Подключение к MCP-клиенту

```json
{
  "mcpServers": {
    "appsec-triage": {
      "command": "docker",
      "env": {"DOCKER_MCP_IN_CONTAINER": "1"},
      "args": ["mcp", "gateway", "run", "--profile", "appsec-triage", "--long-lived", "--cpus", "3", "--memory", "8Gb"]
    }
  }
}
```

Local server entries и profiles описаны в
[документации Docker MCP](https://docs.docker.com/ai/mcp-catalog-and-toolkit/cli/).
Сгенерированный entry на Linux находится в `.local/config/server-linux.json`, минимальный пример —
`docker/server.yaml`. Другие профили и конфигурации клиентов установщик не меняет.

## Инструменты для модели MCP-клиента

- `appsec_get_review_instructions`, `appsec_list_assets`, `appsec_read_asset`;
- `appsec_list_scanners`, `appsec_start_repository_scan`, `appsec_start_scan`;
- `appsec_job_status`, `appsec_job_log`, `appsec_job_result`, `appsec_job_findings`, `appsec_job_report`;
- `read_file`, `search_code`, `lsp_find_symbol`, `lsp_find_usages`, `lsp_outline`,
  `lsp_read_symbol`, `lsp_definition`, `lsp_references`, `lsp_callers`;
- `appsec_save_result`, `appsec_release_checkout`, `appsec_cancel_job`;
- `appsec_send_telegram_result`, `appsec_send_scp_result`.

Промпты доступны как native MCP prompt `appsec_review`, через инструмент
`appsec_get_review_instructions(cwe="CWE-79", ecosystems=["npm"])` и как исходные файлы.
Инструмент всегда включает базу. По CWE и типу находки он добавляет подходящие
шаблоны и их общие фрагменты. Для зависимости с известным CWE действуют оба набора правил.
По `job_id` сервер добавляет контекст экосистем и фреймворков, определённых при сканировании.
Явные `ecosystems` и `stacks` позволяют ограничить контекст конкретным сервисом монорепозитория.
Без задания и явного выбора сервер выдаёт общий контекст.
Поле `layers` перечисляет включённые файлы, `review_policy` содержит правила из
`pipeline.yaml`, а `verdict_schema` задаёт формат вывода по одной находке.
По умолчанию профиль развёртывания — `generic`. Для проекта, где оператор подтвердил
условия из `configs/deployment.yaml`, передайте `deployment_profile="bundled"`.
Конфиги читаются как исходный текст: переменные окружения и секреты не раскрываются.
Подключённая модель должна запросить и применить инструкции: наличие промптов в сервере
само по себе не заставляет произвольный MCP-клиент их выполнять.

Для самостоятельного скана `keep_checkout` по умолчанию `false`: после HTML исходники удаляются.
Чтобы модель MCP-клиента исследовала код после сканеров:

1. Вызвать `appsec_start_repository_scan(projects="URL", keep_checkout=true)`.
2. Дождаться завершения, прочитать `appsec_job_findings(job_id)`.
3. Для каждой находки передать её `review_arguments` в `appsec_get_review_instructions`.
   Собрать доказательства через code/LSP с `target` из поля `source_target` статуса задания
   и применить все полученные слои при вынесении вердикта.
4. Сохранить выводы через `appsec_save_result(project, report_markdown, source_job_id=job_id)`.
   Это добавит отчёт клиента к тому же заданию и удалит checkout.
   Отдельно освободить исходники можно через `appsec_release_checkout(job_id)`.
5. Отправить готовый результат в нужный канал.

Отчёт клиента подписывается как подготовленный MCP-клиентом. Сервер не вызывает модель
и не проверяет её выводы. Одновременно удерживается не более трёх активных/сохранённых checkout.
При завершении процесса MCP-сервера оставшиеся сохранённые checkout также удаляются.

## Telegram

Укажите ID чата в профиле. Токен бота сохраните в `.local/config/telegram.token`. Этот файл доступен контейнеру только для чтения. Команда `read -s` скрывает ввод.

```bash
.venv/bin/python scripts/setup_docker_mcp.py --skip-build --telegram-chat-id 'YOUR_CHAT_ID'
read -rsp 'Telegram bot token: ' telegram_token
printf '\n'
(umask 077; printf '%s\n' "$telegram_token" > .local/config/telegram.token)
chmod 600 .local/config/telegram.token
unset telegram_token
.venv/bin/appsec-scan-projects "https://git.example/team/project.git" --telegram
```

Для отправки из чата переподключите MCP-клиент после настройки профиля. В Windows установщик PowerShell использует секрет Docker Desktop `appsec-triage.telegram_bot_token` и параметры `-EnableTelegram -TelegramChatId 'YOUR_CHAT_ID'`.

Отправляются имя проекта, статус, длительность и HTML. Без HTML отправляется только статус.
Без `--telegram` отправки нет. Модель MCP-клиента может вызвать инструмент доставки отдельно.

## SCP и приватный Git по SSH

Создайте `.local/config/scp-targets.json` по образцу `examples/scp-targets.json`.
Положите в выделенную папку `.local/config` ключ `id_ed25519` и проверенный `known_hosts`.
Не копируйте туда весь домашний `.ssh`. Папка монтируется read-only; для OpenSSH ключ
временно копируется внутри контейнера с правами `600`, затем копия удаляется.
Удалённый каталог из конфигурации должен уже существовать.

```bash
.venv/bin/appsec-scan-projects "https://git.example/team/project.git" --scp default
.venv/bin/appsec-scan-projects "git@git.example:team/project.git" --scp default
```

SCP передаёт ZIP: HTML, summaries, нормализованные findings, сырые отчёты сканеров и
`result.json`. Исходники, SSH-ключи и job log в ZIP не входят.
Назначение выбирается по alias, например `default`. Включены BatchMode и строгая
проверка host key. Выделенный SSH-ключ и known_hosts используются и для приватного Git.
Пароли и токены в Git URL запрещены. Для приватного HTTPS нужна отдельно настроенная
Git-аутентификация в контейнере. При таймауте доставка считается неподтверждённой.

## Хранение и очистка

Отчёты и логи: Docker volume `appsec-mcp-results`, `/out/jobs/<job_id>/`.
Исходники: временный `/work/projects/.mcp-checkouts/<job_id>/source`.
Worker удаляет checkout в `finally`, менеджер повторно проверяет очистку после выхода
или отмены процесса. Поле `checkout_cleanup=removed` подтверждает удаление;
`retained` означает явное сохранение для анализа клиентом, `failed` — ошибку удаления.
Скачанные HTML остаются на хосте.

Gateway должен работать на протяжении пакета: `longLived`/`--long-lived` сохраняет
сервер между tool calls. Реестр job_id находится в памяти. После перезапуска прежние
job_id через MCP недоступны, но артефакты в volume остаются. Файловая система контейнера
с клонами удаляется при его удалении.

## Разработка

```bash
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check src tests --no-cache
docker build -t appsec-triage-mcp:local .
```

Структура перенесённой библиотеки:

```text
src/appsec_triage_mcp/
  core/                  # исходный код AppSec как внутренняя Python-библиотека
    assets/
      prompts/           # CWE, SCA, контекст и stack-промпты
      configs/           # scanner/LSP/pipeline/deployment-конфиги и правила
  assets.py              # выдача промптов и настроек MCP-клиенту
  server.py              # инструменты, native prompt и resource MCP
```

Пакет содержит копию всех 224 runtime-файлов из `appsec_triage/`, `configs/`, `prompts/`.
Исходная папка агента сохранена. Состав и исходные SHA-256 записаны в
[vendor-manifest.json](vendor-manifest.json). Описание адаптаций — в
[vendoring.md](vendoring.md), лицензия — в [LICENSE](../LICENSE).
Legacy provider/agent-модули сохранены как часть библиотеки для дальнейшего переноса
функций; MCP не запускает их оркестратор и не вызывает провайдеров. Шаблон
`configs/providers/llm.yaml` доступен как исходный ресурс, а не как активная конфигурация MCP.
`.env`, ключи, `.git`, виртуальное окружение и результаты старого агента не перенесены.
