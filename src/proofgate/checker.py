"""Agentic claim checker.

``check_claims`` verifies each claim against a pinned :class:`Repo` by
running an agent loop with Muse Spark: the model gathers evidence through
function tools that map to ``repo.py`` (``search_code``, ``read_file``,
``find_symbol``, ``file_exists``, ``list_versions``) and finally returns an
:class:`Evidence` object per claim.

Model rules (also enforced in code where marked [CODE]):
- never mark "supported"/"refuted" without citing a file + line range from
  an actual ``read_file`` call [CODE: downgraded to "unverifiable"].
- a symbol that does not exist at that version, with no close match,
  refutes ``symbol_exists`` claims.
- when a close match exists (renamed/misspelled function), say so in the
  summary.
- mark "unverifiable" rather than guess.
- ``reproducible_impact`` claims stay "unverifiable" (Prompt 4 runs them).

Turn cap and token counting come from ``llm.py`` (``max_tool_turns`` and
``usage``). Every tool call (name + arguments, never the API key) is
appended to a log list so the UI can replay the agent's steps later.
"""

from __future__ import annotations

import json
from typing import Any

from .llm import DEFAULT_MAX_TOOL_TURNS, LLMClient
from .models import Claim, Evidence

SYSTEM_PROMPT = """You verify factual claims about source code at a pinned version.

You have function tools: search_code, read_file, find_symbol, file_exists,
list_versions. Use them to gather evidence BEFORE judging any claim.

Rules:
- NEVER mark a claim "supported" or "refuted" unless you cite a file and a
  line range you actually read with the read_file tool. Search snippets and
  guesses do not count.
- A symbol that does not exist at this version, with no close match from
  find_symbol, REFUTES a symbol_exists claim.
- When find_symbol reports a close match (a renamed or misspelled function),
  say so explicitly in the summary, naming the close match and its location.
- Mark "unverifiable" rather than guess when the evidence is inconclusive.
- reproducible_impact claims (real exploit/impact) are "unverifiable" from
  static inspection alone; do not try to prove them.

Reply with EXACTLY ONE JSON object per turn, no prose, no markdown fences:
- to act: {"tool": "<name>", "arguments": {...}}
- to finish a claim: {"status": "supported|refuted|unverifiable",
  "summary": "<one or two sentences>",
  "file": "<repo-relative path or null>",
  "line_start": <int or null>, "line_end": <int or null>,
  "snippet": "<up to 15 quoted lines or null>"}
"""

TOOL_SCHEMAS = [
    {
        "type": "function",
        "name": "search_code",
        "description": "Substring/regex search over repo text files.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "regex": {"type": "boolean"},
                "max_results": {"type": "integer"},
            },
            "required": ["pattern"],
        },
    },
    {
        "type": "function",
        "name": "read_file",
        "description": "Read numbered lines start..end (max 120 lines).",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start": {"type": "integer"},
                "end": {"type": ["integer", "null"]},
            },
            "required": ["path"],
        },
    },
    {
        "type": "function",
        "name": "find_symbol",
        "description": "Find def/class definitions by name (with close matches).",
        "parameters": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "type": "function",
        "name": "file_exists",
        "description": "Check a repo-relative path exists and is a file.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "type": "function",
        "name": "list_versions",
        "description": "List known tags and recent commits.",
        "parameters": {"type": "object", "properties": {}},
    },
]

_VALID_TOOLS = {t["name"] for t in TOOL_SCHEMAS}

_VALID_STATUSES = ("supported", "refuted", "unverifiable")

#: Cap tool result text folded back into the prompt (bounds token use).
MAX_TOOL_RESULT_CHARS = 6000


def _response_text(response: Any) -> str:
    """Pull plain text out of a Responses API response, a fake, or a string."""
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return output_text
    for block_name in ("output", "outputs"):
        blocks = getattr(response, block_name, None)
        if isinstance(blocks, list):
            chunks: list[str] = []
            for block in blocks:
                if getattr(block, "type", "") == "message":
                    for part in getattr(block, "content", None) or []:
                        text = getattr(part, "text", None)
                        if isinstance(text, str):
                            chunks.append(text)
                elif getattr(block, "type", "") in (
                    "output_text",
                    "reasoning_text",
                ):
                    text = getattr(block, "text", None)
                    if isinstance(text, str):
                        chunks.append(text)
            if chunks:
                return "".join(chunks)
    data = getattr(response, "data", None)
    if isinstance(data, str):
        return data
    text_attr = getattr(response, "text", None)
    if isinstance(text_attr, str):
        return text_attr
    return str(response)


def _native_tool_calls(response: Any) -> list[dict]:
    """Extract provider-native function calls (Responses or Chat API)."""
    calls: list[dict] = []
    outputs = getattr(response, "output", None)
    if isinstance(outputs, list):
        for block in outputs:
            if getattr(block, "type", "") == "function_call":
                name = getattr(block, "name", "")
                raw_args = getattr(block, "arguments", "{}") or "{}"
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else {}
                except (json.JSONDecodeError, TypeError):
                    args = {}
                if name:
                    calls.append({"tool": name, "arguments": args})
        if calls:
            return calls
    choices = getattr(response, "choices", None)
    if isinstance(choices, list) and choices:
        message = getattr(choices[0], "message", None)
        for call in getattr(message, "tool_calls", None) or []:
            func = getattr(call, "function", None)
            name = getattr(func, "name", "") if func else ""
            raw_args = getattr(func, "arguments", "{}") if func else "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else {}
            except (json.JSONDecodeError, TypeError):
                args = {}
            if name:
                calls.append({"tool": name, "arguments": args})
    return calls


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _text_tool_call(text: str) -> dict | None:
    """Parse the JSON tool-call protocol from model text."""
    try:
        payload = json.loads(_strip_fences(text))
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(payload, dict) and isinstance(payload.get("tool"), str):
        args = payload.get("arguments", {})
        return {
            "tool": payload["tool"],
            "arguments": args if isinstance(args, dict) else {},
        }
    return None


def _parse_evidence(text: str, claim_id: str) -> Evidence | None:
    """Parse a final-evidence JSON object from model text."""
    try:
        payload = json.loads(_strip_fences(text))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if isinstance(payload.get("evidence"), dict):
        payload = payload["evidence"]
    if payload.get("status") not in _VALID_STATUSES:
        return None
    snippet = payload.get("snippet")
    if not isinstance(snippet, str):
        snippet = None
    line_start = payload.get("line_start")
    line_end = payload.get("line_end")
    try:
        line_start = None if line_start is None else int(line_start)
        line_end = None if line_end is None else int(line_end)
    except (TypeError, ValueError):
        return None
    file = payload.get("file")
    if file is not None and not isinstance(file, str):
        return None
    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return None
    if snippet is not None and len(snippet.splitlines()) > 15:
        snippet = "\n".join(snippet.splitlines()[:15])
    return Evidence(
        claim_id=claim_id,
        status=payload["status"],
        summary=summary.strip(),
        file=file,
        line_start=line_start,
        line_end=line_end if line_end is not None else line_start,
        snippet=snippet,
    )


def validate_evidence(evidence: Evidence, read_spans: list[tuple]) -> Evidence:
    """Enforce the citation rule: supported/refuted needs a real read.

    ``read_spans`` holds ``(file, line_start, line_end)`` triples from
    successful ``read_file`` tool calls. An Evidence claiming "supported"
    or "refuted" without a file/line covered by one of those spans is
    downgraded to "unverifiable" rather than trusted.
    """
    if evidence.status not in ("supported", "refuted"):
        return evidence
    covered = False
    if evidence.file and evidence.line_start is not None:
        start = evidence.line_start
        end = evidence.line_end if evidence.line_end is not None else start
        for span_file, span_start, span_end in read_spans:
            if (
                span_file == evidence.file
                and span_start <= start
                and end <= span_end
            ):
                covered = True
                break
    if not covered:
        evidence.status = "unverifiable"
        evidence.summary = (
            evidence.summary.rstrip()
            + " [Downgraded: verdict cited no file/line range actually read.]"
        )
    return evidence


def _execute_tool(repo, tool: str, args: dict) -> dict:
    """Run one repo tool; always return a JSON-serializable result."""
    try:
        if tool == "search_code":
            return {
                "ok": True,
                "results": repo.search_code(
                    args.get("pattern", ""),
                    regex=bool(args.get("regex", False)),
                    max_results=int(args.get("max_results", 20)),
                ),
            }
        if tool == "read_file":
            return {
                "ok": True,
                "content": repo.read_file(
                    args.get("path", ""),
                    start=int(args.get("start", 1)),
                    end=(
                        None
                        if args.get("end") is None
                        else int(args["end"])
                    ),
                ),
            }
        if tool == "find_symbol":
            return {"ok": True, "symbols": repo.find_symbol(args.get("name", ""))}
        if tool == "file_exists":
            return {"ok": True, "exists": repo.file_exists(args.get("path", ""))}
        if tool == "list_versions":
            return {"ok": True, "versions": repo.list_versions()}
        return {"ok": False, "error": f"unknown tool: {tool}"}
    except Exception as exc:  # tool errors go back to the model, not up
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _claim_prompt(claim: Claim, repo) -> str:
    target = (
        ", ".join(f"{k}={v}" for k, v in claim.target.items())
        if claim.target
        else "none stated"
    )
    return (
        f"Claim {claim.id} (kind={claim.kind}, check_method={claim.check_method}):\n"
        f"Statement: {claim.statement}\n"
        f"Target hints from the report: {target}\n"
        f"Repo version: {getattr(repo, 'version', '')}\n"
        "Investigate with tools, then reply with the final evidence JSON."
    )


def _check_one_claim(
    claim: Claim, repo, llm, max_turns: int, tool_log: list
) -> Evidence:
    # Reproducible-impact claims need a sandboxed test (Prompt 4); a static
    # agent loop cannot decide them, so leave them unverifiable.
    if claim.kind == "reproducible_impact" or claim.check_method == "test":
        return Evidence(
            claim_id=claim.id,
            status="unverifiable",
            summary=(
                "Reproducible-impact claims need a sandboxed reproduction "
                "test (not run in static checking); left unverifiable."
            ),
        )

    history: list[str] = [_claim_prompt(claim, repo)]
    read_spans: list[tuple] = []
    request_kwargs: dict[str, Any] = {
        "instructions": SYSTEM_PROMPT,
        "tools": TOOL_SCHEMAS,
    }

    for turn in range(max_turns):
        prompt = "\n\n".join(history)
        response = llm.generate(prompt, **request_kwargs)
        text = _response_text(response)

        tool_calls = _native_tool_calls(response)
        single = _text_tool_call(text) if not tool_calls else None
        if single is not None:
            tool_calls = [single]

        if tool_calls:
            for call in tool_calls[:5]:
                tool = call.get("tool", "")
                args = call.get("arguments", {})
                if not isinstance(args, dict):
                    args = {}
                # Log name + arguments only: the API key never appears here.
                tool_log.append(
                    {
                        "claim_id": claim.id,
                        "turn": turn,
                        "tool": tool,
                        "arguments": args,
                    }
                )
                if tool not in _VALID_TOOLS:
                    history.append(
                        f"Tool {tool!r} is unknown. "
                        f"Available: {sorted(_VALID_TOOLS)}."
                    )
                    continue
                result = _execute_tool(repo, tool, args)
                if (
                    tool == "read_file"
                    and result.get("ok")
                    and isinstance(result.get("content"), dict)
                ):
                    content = result["content"]
                    read_spans.append(
                        (content["file"], content["start"], content["end"])
                    )
                rendered = json.dumps(result, default=str)
                history.append(
                    f"Tool {tool}({json.dumps(args)}) -> "
                    f"{rendered[:MAX_TOOL_RESULT_CHARS]}"
                )
            continue

        evidence = _parse_evidence(text, claim.id)
        if evidence is not None:
            return validate_evidence(evidence, read_spans)
        history.append(
            "That reply was neither a tool call nor a final evidence JSON "
            "object. Reply with exactly one JSON object: either "
            '{"tool": ..., "arguments": {...}} or '
            '{"status": ..., "summary": ..., "file": ..., '
            '"line_start": ..., "line_end": ..., "snippet": ...}.'
        )

    return Evidence(
        claim_id=claim.id,
        status="unverifiable",
        summary=(
            "Tool budget exhausted before the checker gathered enough "
            "evidence; left unverifiable rather than guessing."
        ),
    )


def check_claims(
    claims: list[Claim],
    repo,
    client: LLMClient | None = None,
    tool_log: list | None = None,
) -> list[Evidence]:
    """Check each claim against ``repo`` with the model agent loop.

    Args:
        claims: Atomic claims from :func:`claims.extract_claims`.
        repo: Pinned :class:`Repo` to inspect (tools only read from it).
        client: Optional ``LLMClient`` (tests inject a mock). When omitted
            a default client is created, which requires ``MODEL_API_KEY``.
        tool_log: Optional list receiving one entry per tool call
            (``claim_id``, ``turn``, ``tool``, ``arguments``) for UI replay.

    Returns:
        One :class:`Evidence` per claim, in input order.
    """
    llm = client if client is not None else LLMClient()
    log: list = tool_log if tool_log is not None else []
    max_turns = getattr(llm, "max_tool_turns", DEFAULT_MAX_TOOL_TURNS) or 1
    max_turns = max(1, int(max_turns))
    return [_check_one_claim(c, repo, llm, max_turns, log) for c in claims]
