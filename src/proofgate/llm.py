"""Meta Model API client wrapper for ProofGate.

Uses the OpenAI Python SDK pointed at the Meta Model API endpoint.
The API key is read ONLY from the ``MODEL_API_KEY`` environment variable
and is never printed, logged, or written anywhere.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


BASE_URL = "https://api.meta.ai/v1"
DEFAULT_MODEL = "muse-spark-1.3"
JUDGE_MODEL = "muse-wonder-1.0"
DEFAULT_MAX_TOOL_TURNS = 15


@dataclass
class TokenUsage:
    """Simple token/cost counter per audit."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    requests: int = 0

    def add(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        self.total_tokens += prompt_tokens + completion_tokens
        self.requests += 1

    def reset(self) -> None:
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.requests = 0


class LLMClient:
    """Thin wrapper around the OpenAI SDK Responses API.

    Args:
        api_key: Optional explicit key. When omitted, read from
            the ``MODEL_API_KEY`` environment variable.
        default_model: Model used for general calls.
        judge_model: Model used for verdict judging, with automatic
            fallback to ``default_model`` if it errors.
        max_tool_turns: Hard cap on agentic tool-calling turns.
    """

    def __init__(
        self,
        api_key: str | None = None,
        default_model: str = DEFAULT_MODEL,
        judge_model: str = JUDGE_MODEL,
        max_tool_turns: int = DEFAULT_MAX_TOOL_TURNS,
    ) -> None:
        key = api_key if api_key is not None else os.environ.get("MODEL_API_KEY")
        if not key:
            raise RuntimeError(
                "MODEL_API_KEY is not set. "
                "Set the MODEL_API_KEY environment variable to your Meta Model API key."
            )
        self._api_key = key
        self.default_model = default_model
        self.judge_model = judge_model
        self.max_tool_turns = max_tool_turns
        self.usage = TokenUsage()
        self._client = None  # Lazily created so import never needs a key.

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(base_url=BASE_URL, api_key=self._api_key)
        return self._client

    def _record_usage(self, response) -> None:
        try:
            usage = getattr(response, "usage", None)
            if usage is None:
                return
            prompt = int(getattr(usage, "input_tokens", 0) or 0)
            completion = int(getattr(usage, "output_tokens", 0) or 0)
            self.usage.add(prompt, completion)
        except (TypeError, ValueError):
            return

    def generate(self, prompt: str, model: str | None = None, **kwargs):
        """Single Responses API call. Returns the raw response object."""
        client = self._get_client()
        response = client.responses.create(
            model=model or self.default_model, input=prompt, **kwargs
        )
        self._record_usage(response)
        return response

    def judge(self, prompt: str, **kwargs):
        """Verdict call: try the judge model, fall back to default on error."""
        try:
            return self.generate(prompt, model=self.judge_model, **kwargs)
        except Exception:
            return self.generate(prompt, model=self.default_model, **kwargs)

    def run_tool_loop(self, start_prompt: str, step_fn, model: str | None = None):
        """Run at most ``max_tool_turns`` agentic turns.

        ``step_fn`` receives ``(turn_index, last_response)`` and must return
        either a new prompt string to continue or ``None`` to stop.
        """
        last_response = self.generate(start_prompt, model=model)
        for turn in range(1, self.max_tool_turns):
            nxt = step_fn(turn, last_response)
            if nxt is None:
                break
            last_response = self.generate(nxt, model=model)
        return last_response
