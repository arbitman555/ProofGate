"""Meta Model API client wrapper for ProofGate.

Uses the OpenAI Python SDK pointed at the Meta Model API endpoint.
The API key is read ONLY from the ``MODEL_API_KEY`` environment variable
and is never printed, logged, or written anywhere.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field


BASE_URL = "https://api.meta.ai/v1"
DEFAULT_MODEL = "muse-spark-1.3"
JUDGE_MODEL = "muse-wonder-1.0"
DEFAULT_MAX_TOOL_TURNS = 8

#: Reasoning effort for claim extraction. Live probe on the Meta endpoint
#: (demo/reports/01_fabricated_jwt.md extraction): low=18.2s valid JSON
#: (8 claims) vs medium=37.3s valid JSON (11 claims). Low kept for
#: extraction only; claim-count variance is a watch item.
DEFAULT_REASONING_EFFORT = "low"

#: Reasoning effort for the repro-test prompt. Kept at medium: the model
#: must emit parsable, sandbox-clean pytest code, which suffered at low
#: effort (unparsable test code in the 01 live audit).
REPRO_REASONING_EFFORT = "medium"

#: HTTP statuses worth retrying (transient). Anything else raises at once.
RETRYABLE_STATUS_CODES = frozenset({429, 503})
MAX_RETRIES = 3


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
        self._lock = threading.Lock()
        self._client = None  # Lazily created so import never needs a key.

    def _get_client(self):
        # Double-checked locking: created once, shared by worker threads.
        if self._client is None:
            with self._lock:
                if self._client is None:
                    from openai import OpenAI

                    self._client = OpenAI(
                        base_url=BASE_URL, api_key=self._api_key
                    )
        return self._client

    def warmup(self):
        """Create the underlying HTTP client now, before threads start."""
        self._get_client()

    def _record_usage(self, response) -> None:
        try:
            usage = getattr(response, "usage", None)
            if usage is None:
                return
            prompt = int(getattr(usage, "input_tokens", 0) or 0)
            completion = int(getattr(usage, "output_tokens", 0) or 0)
            with self._lock:
                self.usage.add(prompt, completion)
        except (TypeError, ValueError):
            return

    def generate(self, prompt: str, model: str | None = None, **kwargs):
        """Single Responses API call. Returns the raw response object.

        Retries HTTP 429/503 with exponential backoff (1s, 2s, 4s; at most
        3 retries), then raises. The API key is never logged or included in
        any message; only the status code drives the retry decision.
        """
        client = self._get_client()
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = client.responses.create(
                    model=model or self.default_model, input=prompt, **kwargs
                )
            except Exception as exc:
                status = getattr(exc, "status_code", None)
                if status in RETRYABLE_STATUS_CODES and attempt < MAX_RETRIES:
                    time.sleep(2**attempt)
                    continue
                raise
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
