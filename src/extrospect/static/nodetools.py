"""Optional Node.js helpers (webcrack, prettier, retire). Missing tools degrade gracefully."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from extrospect.config import ToolsConfig
from extrospect.util import find_executable


@dataclass(frozen=True)
class NodeTools:
    webcrack: str | None
    prettier: str | None
    retire: str | None

    def available(self) -> dict[str, bool]:
        return {
            "webcrack": bool(self.webcrack),
            "prettier": bool(self.prettier),
            "retire": bool(self.retire),
        }


def resolve_tools(cfg: ToolsConfig) -> NodeTools:
    return NodeTools(
        webcrack=find_executable("webcrack", cfg.webcrack),
        prettier=find_executable("prettier", cfg.prettier),
        retire=find_executable("retire", cfg.retire),
    )


def run_tool(
    cmd: list[str], *, input_text: str | None = None, timeout: float = 90.0
) -> subprocess.CompletedProcess[str]:
    """Run a helper without a shell; never raises for non-zero exit codes."""
    return subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def tool_version(path: str | None, timeout: float = 20.0) -> str | None:
    if not path:
        return None
    try:
        result = run_tool([path, "--version"], timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0] if output else None


__all__ = ["NodeTools", "resolve_tools", "run_tool", "tool_version"]
