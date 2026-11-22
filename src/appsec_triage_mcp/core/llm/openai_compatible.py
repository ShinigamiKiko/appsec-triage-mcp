"""OpenAI-compatible Chat Completions transport used for every configured model."""

from __future__ import annotations

import json

from .base import BaseHTTPClient, LLMError, LLMTruncated, ToolCall, ToolTurn, _UnparsableReply, tool_arguments


class OpenAICompatibleClient(BaseHTTPClient):
    _NATIVE_TOOLS = True

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        return headers

    def _base_payload(self, messages: list[dict]) -> dict:
        payload: dict = {"model": self.model, "messages": messages}
        if self.cfg.temperature is not None:
            payload["temperature"] = self.cfg.temperature
        payload[self.cfg.output_token_field] = self._max_tokens()
        payload.update(self.cfg.options)
        if self.cfg.top_p is not None:
            payload["top_p"] = self.cfg.top_p
        if self.cfg.stop:
            payload["stop"] = self.cfg.stop
        return payload

    def _build_payload(self, system: str, user: str, json_schema: dict | None) -> tuple[str, dict]:
        payload = self._base_payload([
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ])
        if self.cfg.json_mode == "json_schema" and json_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "appsec_triage", "strict": True, "schema": json_schema},
            }
        elif self.cfg.json_mode == "json_object":
            payload["response_format"] = {"type": "json_object"}
            if json_schema:
                payload["messages"][0]["content"] += (
                    "\n\n## Output contract\n"
                    "Respond with one JSON object that validates against this JSON Schema. "
                    "Use exactly these field names, include every required field, and add no others:\n"
                    + json.dumps(json_schema, ensure_ascii=False)
                )
            elif "json" not in (system + user).lower():
                payload["messages"][0]["content"] += "\n\nRespond with one JSON object."
        return "/chat/completions", payload

    def _parse(self, body: dict) -> tuple[str, int | None, int | None]:
        choices = body.get("choices") or []
        if not choices:
            raise LLMError(f"{self.name}: response had no choices: {str(body)[:300]}")
        choice = choices[0]
        message = choice.get("message") or {}
        text = message.get("content") or ""
        if choice.get("finish_reason") == "length":
            raise LLMTruncated(f"{self.name}: response truncated at max_tokens={self._max_tokens()}")
        reasoning = message.get("reasoning_content") or ""
        if not text.strip() and reasoning.strip():
            raise _UnparsableReply(
                f"{self.name}: модель вернула только рассуждение ({len(reasoning)} симв.), "
                f"ответ пуст, finish_reason={choice.get('finish_reason')!r}"
            )
        usage = body.get("usage") or {}
        return text, usage.get("prompt_tokens"), usage.get("completion_tokens")

    def _tool_payload(self, messages: list[dict], tools: list[dict]) -> tuple[str, dict]:
        payload = self._base_payload(messages)
        payload["tools"] = tools
        return "/chat/completions", payload

    def _tool_parse(self, body: dict) -> ToolTurn:
        choices = body.get("choices") or []
        if not choices:
            raise LLMError(f"{self.name}: response had no choices: {str(body)[:300]}")
        choice = choices[0]
        message = choice.get("message") or {}
        if choice.get("finish_reason") == "length":
            raise LLMTruncated(f"{self.name}: response truncated at max_tokens={self._max_tokens()}")
        raw_calls = [item for item in (message.get("tool_calls") or []) if isinstance(item, dict)]
        calls = [
            ToolCall(
                id=str(item.get("id") or f"call_{index}"),
                name=str((item.get("function") or {}).get("name") or ""),
                arguments=tool_arguments((item.get("function") or {}).get("arguments")),
            )
            for index, item in enumerate(raw_calls)
        ]
        text = message.get("content") or ""
        echo: dict = {"role": "assistant", "content": text}
        if raw_calls:
            echo["tool_calls"] = raw_calls
        if isinstance(message.get("reasoning_content"), str):
            echo["reasoning_content"] = message["reasoning_content"]
        usage = body.get("usage") or {}
        return ToolTurn(text, calls, echo, usage.get("prompt_tokens"), usage.get("completion_tokens"))

    def tool_result_message(self, call: ToolCall, content: str) -> dict:
        return {"role": "tool", "tool_call_id": call.id, "content": content}
