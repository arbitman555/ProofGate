"""Skeleton tests: every module imports; llm.py requires MODEL_API_KEY."""

import os


def test_all_modules_import():
    import proofgate
    import proofgate.checker
    import proofgate.claims
    import proofgate.cli
    import proofgate.llm
    import proofgate.models
    import proofgate.repo
    import proofgate.sandbox
    import proofgate.verdict

    assert proofgate.__version__ == "0.1.0"


def test_llm_requires_api_key(monkeypatch):
    from proofgate import llm

    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    try:
        llm.LLMClient()
    except RuntimeError as exc:
        assert "MODEL_API_KEY" in str(exc)
    else:
        raise AssertionError("LLMClient() should raise without MODEL_API_KEY")


def test_llm_does_not_read_other_vars(monkeypatch):
    import proofgate.llm as llm_mod

    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "dummy-should-be-ignored")
    monkeypatch.setenv("API_KEY", "dummy-should-be-ignored")
    try:
        llm_mod.LLMClient()
    except RuntimeError as exc:
        assert "MODEL_API_KEY" in str(exc)
    else:
        raise AssertionError("LLMClient() must read ONLY MODEL_API_KEY")

    # Key passed explicitly still works without env.
    os.environ.pop("MODEL_API_KEY", None)
    client = llm_mod.LLMClient(api_key="dummy-explicit-key")
    assert client.usage.total_tokens == 0
    assert client.max_tool_turns == 15
