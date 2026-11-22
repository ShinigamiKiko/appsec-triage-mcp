"""Telegram Bot API delivery for completed AppSec jobs."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


class TelegramError(ValueError):
    pass


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str, base_url: str = "https://api.telegram.org") -> None:
        self.token = token
        self.chat_id = chat_id
        self.base_url = base_url.rstrip("/")

    @classmethod
    def from_env(cls, chat_id: str | None = None) -> TelegramNotifier:
        token = os.environ.get("APPSEC_MCP_TELEGRAM_BOT_TOKEN", "").strip()
        token_file = os.environ.get("APPSEC_MCP_TELEGRAM_BOT_TOKEN_FILE")
        if not token and token_file:
            try:
                token = Path(token_file).read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError) as exc:
                raise TelegramError("Cannot read the configured Telegram token file") from exc
        selected_chat = (chat_id or os.environ.get("APPSEC_MCP_TELEGRAM_CHAT_ID", "")).strip()
        if not token or not selected_chat:
            raise TelegramError(
                "Set APPSEC_MCP_TELEGRAM_BOT_TOKEN and APPSEC_MCP_TELEGRAM_CHAT_ID, or pass chat_id explicitly."
            )
        return cls(token, selected_chat)

    def send_result(self, result: dict[str, Any], report: Path | None = None) -> dict[str, Any]:
        project = result.get("project")
        if not project:
            raise TelegramError("The selected job has no scanned project name.")
        text = "\n".join(
            [
                "AppSec scan result",
                f"Project: {project}",
                f"Job: {result['job_id']}",
                f"Type: {result['kind']}",
                f"Status: {result['status']}",
                f"Duration: {result['duration_s']} s",
            ]
        )
        if report is None:
            payload = self._request("sendMessage", {"chat_id": self.chat_id, "text": text})
        else:
            if report.stat().st_size > 45 * 1024 * 1024:
                raise TelegramError("The report exceeds the 45 MiB document size supported by this server.")
            payload = self._request(
                "sendDocument",
                {"chat_id": self.chat_id, "caption": text},
                document=(report.name, report.read_bytes(), "text/html"),
            )
        message = payload.get("result", {})
        return {
            "job_id": result["job_id"],
            "project": project,
            "status": result["status"],
            "telegram_message_id": message.get("message_id"),
            "report_sent": report is not None,
            "report": report.name if report else None,
        }

    def _request(
        self,
        method: str,
        fields: dict[str, str],
        **files: tuple[str, bytes, str],
    ) -> dict[str, Any]:
        if files:
            content_type, body = self._multipart(fields, files)
            data = body
        else:
            content_type = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(fields).encode()
        request = urllib.request.Request(
            f"{self.base_url}/bot{self.token}/{method}",
            data=data,
            headers={"Content-Type": content_type},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError) as exc:
            detail = str(exc).replace(self.token, "***")
            raise TelegramError(f"Telegram request failed: {detail}") from None
        if not isinstance(payload, dict) or not payload.get("ok"):
            description = payload.get("description", "unknown error") if isinstance(payload, dict) else "invalid response"
            raise TelegramError(f"Telegram API rejected the request: {str(description).replace(self.token, '[REDACTED_SECRET]')}")
        return payload

    @staticmethod
    def _multipart(
        fields: dict[str, str],
        files: dict[str, tuple[str, bytes, str]],
    ) -> tuple[str, bytes]:
        boundary = uuid.uuid4().hex
        body = bytearray()
        for name, value in fields.items():
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
            body.extend(str(value).encode())
            body.extend(b"\r\n")
        for name, (filename, content, content_type) in files.items():
            if len(content) > 45 * 1024 * 1024:
                raise TelegramError("The report exceeds the 45 MiB document size supported by this server.")
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
            )
            body.extend(f"Content-Type: {content_type}\r\n\r\n".encode())
            body.extend(content)
            body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode())
        return f"multipart/form-data; boundary={boundary}", bytes(body)
