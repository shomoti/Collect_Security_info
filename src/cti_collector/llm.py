from __future__ import annotations

import json
import logging
from typing import Any

import requests


def extract_json_block(text: str) -> str:
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and start < end:
        return text[start : end + 1]
    raise ValueError("No JSON object found")


class LLMClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        temperature: float,
        timeout_seconds: int,
        max_retries: int,
        system_prompt: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.system_prompt = system_prompt
        self.logger = logging.getLogger(__name__)

    def summarize(self, user_prompt: str) -> dict[str, Any]:
        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(endpoint, headers=headers, json=payload, timeout=self.timeout_seconds)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                json_text = extract_json_block(content)
                return json.loads(json_text)
            except Exception as exc:
                last_error = exc
                self.logger.warning(
                    "llm attempt failed",
                    extra={"extra": {"attempt": attempt, "error": str(exc)}},
                )

        raise RuntimeError(f"LLM summarize failed after retries: {last_error}")
