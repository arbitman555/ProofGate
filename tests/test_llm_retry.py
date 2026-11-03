"""Tests for LLMClient retry/backoff (no network; faked transport)."""

from __future__ import annotations

import threading
import types

import pytest

from proofgate.llm import LLMClient


class _StatusErr(Exception):
    def __init__(self, code: int):
        self.status_code = code
        super().__init__(f"http {code}")


def _client_with(create_fn, monkeypatch) -> LLMClient:
    client = LLMClient(api_key="dummy-key-never-logged")
    fake = types.SimpleNamespace(
        responses=types.SimpleNamespace(create=create_fn)
    )
    monkeypatch.setattr(client, "_get_client", lambda: fake)
    return client


def test_generate_retries_once_on_429_then_returns(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("proofgate.llm.time.sleep", sleeps.append)
    calls: list = []

    def create(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise _StatusErr(429)
        return types.SimpleNamespace(usage=None)

    client = _client_with(create, monkeypatch)
    assert client.generate("hi") is not None
    assert len(calls) == 2
    assert sleeps == [1]


def test_generate_does_not_retry_on_400(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("proofgate.llm.time.sleep", sleeps.append)
    calls: list = []

    def create(**kwargs):
        calls.append(kwargs)
        raise _StatusErr(400)

    client = _client_with(create, monkeypatch)
    with pytest.raises(_StatusErr):
        client.generate("hi")
    assert len(calls) == 1
    assert sleeps == []


def test_generate_gives_up_after_3_retries_on_503(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("proofgate.llm.time.sleep", sleeps.append)
    calls: list = []

    def create(**kwargs):
        calls.append(kwargs)
        raise _StatusErr(503)

    client = _client_with(create, monkeypatch)
    with pytest.raises(_StatusErr):
        client.generate("hi")
    assert len(calls) == 4  # initial + 3 retries
    assert sleeps == [1, 2, 4]
    assert "dummy-key-never-logged" not in str(calls)


def test_record_usage_is_thread_safe():
    client = LLMClient(api_key="dummy")
    resp = types.SimpleNamespace(
        usage=types.SimpleNamespace(input_tokens=1, output_tokens=2)
    )

    def hammer():
        for _ in range(500):
            client._record_usage(resp)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert client.usage.prompt_tokens == 4000
    assert client.usage.completion_tokens == 8000
    assert client.usage.requests == 4000
