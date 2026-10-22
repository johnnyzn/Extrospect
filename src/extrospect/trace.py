"""JSONL traces: every LLM call and agent tool step of an analysis, replayable later.

One file per trace id under ``<data_dir>/traces``. With ``llm.trace_full_content`` the
full request messages and responses are stored (local only), which is what makes
``extrospect trace show <id>`` able to replay a complete agent trajectory.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from extrospect.util import one_line, sha256_text


class Tracer:
    def __init__(
        self,
        trace_id: str,
        directory: Path | None,
        full_content: bool = True,
        label: str | None = None,
    ):
        self.trace_id = trace_id
        self.path = directory / f"{trace_id}.jsonl" if directory else None
        self.full_content = full_content
        self._lock = threading.Lock()
        self.events: list[dict[str, Any]] = []
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        if label:
            self.log({"type": "start", "label": label})

    def log(self, event: dict[str, Any]) -> None:
        record = {"ts": round(time.time(), 3), "trace_id": self.trace_id, **event}
        with self._lock:
            self.events.append(record)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def llm_call(
        self,
        *,
        span: str,
        model: str,
        prompt_version: str,
        messages: list[dict[str, Any]],
        response: dict[str, Any],
        usage: dict[str, Any],
        latency_ms: int,
        finish_reason: str,
        error: str | None = None,
    ) -> None:
        request_text = json.dumps(messages, ensure_ascii=False, default=str, sort_keys=True)
        response_text = json.dumps(response, ensure_ascii=False, default=str, sort_keys=True)
        event: dict[str, Any] = {
            "type": "llm_call",
            "span": span,
            "model": model,
            "prompt_version": prompt_version,
            "input_hash": sha256_text(request_text)[:16],
            "output_hash": sha256_text(response_text)[:16],
            "usage": usage,
            "latency_ms": latency_ms,
            "finish_reason": finish_reason,
        }
        if error:
            event["error"] = error
        if self.full_content:
            event["request"] = messages
            event["response"] = response
        self.log(event)

    def tool_call(
        self, *, span: str, name: str, arguments: dict[str, Any], result: str, latency_ms: int
    ) -> None:
        event: dict[str, Any] = {
            "type": "tool_call",
            "span": span,
            "name": name,
            "arguments": arguments,
            "result_hash": sha256_text(result)[:16],
            "result_chars": len(result),
            "latency_ms": latency_ms,
        }
        if self.full_content:
            event["result"] = result
        self.log(event)


def list_traces(directory: Path, limit: int = 20) -> list[dict[str, Any]]:
    if not directory.is_dir():
        return []
    files = sorted(directory.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
    infos = []
    for path in files:
        events = _read(path)
        label = next((e.get("label") for e in events if e.get("type") == "start"), None)
        cost = sum(
            float((e.get("usage") or {}).get("cost_usd", 0.0))
            for e in events
            if e.get("type") == "llm_call"
        )
        infos.append(
            {"trace_id": path.stem, "label": label, "events": len(events), "cost_usd": cost}
        )
    return infos


def _read(path: Path) -> list[dict[str, Any]]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def load_trace(directory: Path, trace_id: str) -> list[dict[str, Any]]:
    path = directory / f"{trace_id}.jsonl"
    if not path.is_file() or path.resolve().parent != directory.resolve():
        return []
    return _read(path)


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    return "" if content is None else str(content)


def render_trace(events: list[dict[str, Any]], full: bool = False) -> str:
    """Human-readable replay of a trace (agent trajectory)."""
    lines: list[str] = []
    total_cost = 0.0
    for event in events:
        kind = event.get("type")
        if kind == "start":
            lines.append(f"# trace {event.get('trace_id')} - {event.get('label')}")
        elif kind == "llm_call":
            usage = event.get("usage") or {}
            total_cost += float(usage.get("cost_usd", 0.0))
            lines.append(
                f"[{event.get('span')}] LLM {event.get('model')} ({event.get('prompt_version')}) "
                f"in={usage.get('input_tokens', 0)} out={usage.get('output_tokens', 0)} "
                f"cache_read={usage.get('cache_read_tokens', 0)} ${float(usage.get('cost_usd', 0.0)):.4f} "
                f"{event.get('latency_ms')}ms finish={event.get('finish_reason')}"
                + (f" ERROR={event.get('error')}" if event.get("error") else "")
            )
            response = event.get("response") or {}
            text = _content_text(response.get("content"))
            if text:
                lines.append("    assistant: " + (text if full else one_line(text, 300)))
            for call in response.get("tool_calls") or []:
                function = call.get("function") or {}
                lines.append(
                    f"    -> {function.get('name')}({one_line(str(function.get('arguments')), 300)})"
                )
            if full:
                for message in event.get("request") or []:
                    lines.append(
                        f"    <{message.get('role')}> {_content_text(message.get('content'))}"
                    )
        elif kind == "tool_call":
            result = event.get("result") or ""
            lines.append(
                f"[{event.get('span')}] tool {event.get('name')}({one_line(json.dumps(event.get('arguments'), ensure_ascii=False), 200)}) "
                f"-> {event.get('result_chars')} chars in {event.get('latency_ms')}ms"
            )
            if result:
                lines.append("    " + (result if full else one_line(result, 300)))
        elif kind == "stage":
            lines.append(
                f"== {event.get('stage')}: {one_line(json.dumps(event.get('data'), ensure_ascii=False, default=str), 400)}"
            )
        else:
            lines.append(one_line(json.dumps(event, ensure_ascii=False, default=str), 400))
    lines.append(f"# total LLM cost ${total_cost:.4f}")
    return "\n".join(lines)


__all__ = ["Tracer", "list_traces", "load_trace", "render_trace"]
