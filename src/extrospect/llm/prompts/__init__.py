"""Versioned prompt templates (``<name>_v<N>.md``). Bump the version when a prompt changes:
the version is part of every cache key and trace record."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from importlib import resources

CURRENT = {
    "triage": "triage_v1",
    "investigator": "investigator_v1",
    "verifier": "verifier_v1",
    "listing_extract": "listing_extract_v1",
    "host_audit": "host_audit_v1",
}


@dataclass(frozen=True)
class Prompt:
    name: str
    version: str
    text: str

    def render(self, **values: str) -> str:
        """Replace ``{{key}}`` placeholders (single braces are left alone for code)."""
        text = self.text
        for key, value in values.items():
            text = text.replace("{{" + key + "}}", value)
        return text


@cache
def load_prompt(name: str) -> Prompt:
    version = CURRENT.get(name, name)
    text = (
        resources.files("extrospect.llm.prompts")
        .joinpath(f"{version}.md")
        .read_text(encoding="utf-8")
    )
    return Prompt(name=name, version=version, text=text.strip() + "\n")


__all__ = ["CURRENT", "Prompt", "load_prompt"]
