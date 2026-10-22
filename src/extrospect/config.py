"""Settings: model choice, budgets, thresholds, tool paths and storage locations.

Precedence (low -> high): built-in defaults < TOML config file < environment variables <
explicit overrides (CLI flags / MCP arguments).

Config file: ``$EXTROSPECT_CONFIG`` or ``<user config dir>/extrospect/config.toml``.
Generate a commented template with ``extrospect config init``.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

from platformdirs import user_cache_dir, user_config_dir, user_data_dir
from pydantic import BaseModel, ConfigDict, Field

from extrospect import __version__

# Bump when analysis logic changes in a way that invalidates cached reports.
PIPELINE_VERSION = f"{__version__}+p1"
APP_NAME = "extrospect"


class _Section(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_assignment=True)


class ModelPrice(_Section):
    """USD per million tokens; used when litellm has no price for a model."""

    input: float
    output: float
    cache_read: float | None = None
    cache_write: float | None = None


class LlmModelConfig(_Section):
    model: str
    max_tokens: int = 4096
    # Some current models reject non-default sampling parameters; leave unset unless needed.
    temperature: float | None = None
    # Passed verbatim to litellm.completion (e.g. {"reasoning_effort": "low"},
    # {"extra_headers": {...}}, {"api_base": "http://localhost:11434"}).
    extra_params: dict[str, Any] = Field(default_factory=dict)
    # "tool": structured output through a tool call; "json": JSON in plain text (for
    # local models without tool-calling support).
    output_mode: Literal["tool", "json"] = "tool"


class LlmConfig(_Section):
    triage: LlmModelConfig = Field(
        default_factory=lambda: LlmModelConfig(
            model="anthropic/claude-haiku-4-5", max_tokens=4096, temperature=0.0
        )
    )
    investigator: LlmModelConfig = Field(
        default_factory=lambda: LlmModelConfig(
            model="anthropic/claude-sonnet-5-5", max_tokens=16000
        )
    )
    verifier: LlmModelConfig = Field(
        default_factory=lambda: LlmModelConfig(
            model="anthropic/claude-haiku-4-5", max_tokens=1024, temperature=0.0
        )
    )
    extractor: LlmModelConfig = Field(
        default_factory=lambda: LlmModelConfig(
            model="anthropic/claude-haiku-4-5", max_tokens=2048, temperature=0.0
        )
    )
    timeout_s: float = 180.0
    max_retries: int = 4
    prompt_caching: bool = True
    # Model to retry with when a provider declines a request (finish_reason=content_filter).
    refusal_fallback_model: str | None = None
    # Store full prompts/responses in traces so agent trajectories can be replayed.
    trace_full_content: bool = True
    pricing: dict[str, ModelPrice] = Field(
        default_factory=lambda: {
            # Fallback prices (USD / MTok) if litellm's price map lacks a model.
            "claude-haiku-4-5": ModelPrice(
                input=1.0, output=5.0, cache_read=0.10, cache_write=1.25
            ),
            "claude-sonnet-5-5": ModelPrice(
                input=2.0, output=10.0, cache_read=0.20, cache_write=2.5
            ),
            "claude-opus-5-5": ModelPrice(input=4.0, output=20.0, cache_read=0.20, cache_write=5.0),
        }
    )


class BudgetConfig(_Section):
    investigator_max_steps: int = 12
    investigator_max_input_tokens: int = 60_000
    investigator_max_cost_usd: float = 0.15
    triage_batch_size: int = 5
    max_slice_tokens_total: int = 24_000  # Router #1: total tokens of slices sent to triage
    max_slices: int = 40
    analysis_max_cost_usd: float = 0.30  # hard stop for a single extension
    tool_result_max_chars: int = 12_000


class RouterConfig(_Section):
    skip_llm_capability_below: float = 0.2
    benign_suspicion_below: float = 0.3
    escalate_suspicion_at: float = 0.6
    escalate_capability_unclear_at: float = 0.7
    knn_escalate_similarity: float = 0.92


class FuseConfig(_Section):
    capability_exponent: float = 0.5
    evidence_exponent: float = 0.7
    reach_weights: dict[str, float] = Field(
        default_factory=lambda: {"yes": 1.0, "unknown": 0.4, "no": 0.1}
    )
    epss_field: Literal["percentile", "probability"] = "percentile"
    # Used for Ev when a finding has no EPSS score (offline, no CVE id, ...).
    severity_fallback: dict[str, float] = Field(
        default_factory=lambda: {"low": 0.1, "medium": 0.25, "high": 0.45, "critical": 0.6}
    )
    llm_weight: float = 0.7
    gbm_weight: float = 0.3
    malicious_floor: int = 80
    first_party_multiplier: float = 0.5
    # Upper bounds (inclusive) of each level; above "high" is "critical".
    level_thresholds: dict[str, int] = Field(
        default_factory=lambda: {"benign": 15, "low": 35, "medium": 60, "high": 80}
    )
    # Verifier conflict rule: capability at/above this + exfiltration sinks needs proof.
    conflict_capability: float = 0.8


class StaticConfig(_Section):
    max_unpack_bytes: int = 200 * 1024 * 1024
    max_unpack_files: int = 20_000
    max_parse_bytes: int = 6 * 1024 * 1024  # larger JS files are not parsed
    slice_max_lines: int = 150
    slice_max_tokens: int = 4_000
    caller_depth: int = 2
    format_minified: bool = True
    deobfuscate: bool = True
    strip_libraries: bool = True
    retire_mode: Literal["auto", "cli", "python", "off"] = "auto"
    long_string_threshold: int = 200


class ToolsConfig(_Section):
    """Optional Node.js helpers. ``None`` = look up on PATH."""

    webcrack: str | None = None
    prettier: str | None = None
    retire: str | None = None
    timeout_s: float = 90.0


class NetworkConfig(_Section):
    offline: bool = False
    user_agent: str = f"extrospect/{__version__} (+https://github.com/johnnyzn/Extrospect)"
    timeout_s: float = 20.0
    crx_prodversion: str = "150.0.0.0"
    webstore_requests_per_s: float = 1.0
    fetch_listing: bool = True
    epss: bool = True
    rdap: bool = True
    advisories: bool = True


class KnowledgeConfig(_Section):
    # "hash" (local, free, deterministic) | "litellm:<model>" | "st:<sentence-transformers model>"
    embedding_model: str = "hash"
    vector_backend: Literal["auto", "lancedb", "simple"] = "auto"
    listing_ttl_days: int = 7
    intel_top_k: int = 5
    use_builtin_intel: bool = True


class PathsConfig(_Section):
    data_dir: Path = Field(default_factory=lambda: Path(user_data_dir(APP_NAME, appauthor=False)))
    cache_dir: Path = Field(default_factory=lambda: Path(user_cache_dir(APP_NAME, appauthor=False)))

    @property
    def cache_db(self) -> Path:
        return self.cache_dir / "cache.sqlite3"

    @property
    def work_dir(self) -> Path:
        return self.cache_dir / "work"

    @property
    def downloads_dir(self) -> Path:
        return self.cache_dir / "downloads"

    @property
    def traces_dir(self) -> Path:
        return self.data_dir / "traces"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def knowledge_dir(self) -> Path:
        return self.data_dir / "knowledge"

    @property
    def models_dir(self) -> Path:
        return self.data_dir / "models"


class Settings(_Section):
    language: str = "auto"
    llm: LlmConfig = Field(default_factory=LlmConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    router: RouterConfig = Field(default_factory=RouterConfig)
    fuse: FuseConfig = Field(default_factory=FuseConfig)
    static: StaticConfig = Field(default_factory=StaticConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    knowledge: KnowledgeConfig = Field(default_factory=KnowledgeConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)

    def ensure_dirs(self) -> None:
        for path in (
            self.paths.data_dir,
            self.paths.cache_dir,
            self.paths.work_dir,
            self.paths.downloads_dir,
            self.paths.traces_dir,
            self.paths.reports_dir,
            self.paths.knowledge_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


def default_config_path() -> Path:
    env = os.environ.get("EXTROSPECT_CONFIG")
    if env:
        return Path(env).expanduser()
    return Path(user_config_dir(APP_NAME, appauthor=False)) / "config.toml"


def _deep_merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _env_overrides() -> dict[str, Any]:
    env = os.environ
    data: dict[str, Any] = {}

    def put(path: tuple[str, ...], value: Any) -> None:
        node = data
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = value

    if env.get("EXTROSPECT_DATA_DIR"):
        put(("paths", "data_dir"), env["EXTROSPECT_DATA_DIR"])
    if env.get("EXTROSPECT_CACHE_DIR"):
        put(("paths", "cache_dir"), env["EXTROSPECT_CACHE_DIR"])
    if env.get("EXTROSPECT_OFFLINE", "").lower() in {"1", "true", "yes"}:
        put(("network", "offline"), True)
    for role in ("triage", "investigator", "verifier", "extractor"):
        value = env.get(f"EXTROSPECT_{role.upper()}_MODEL")
        if value:
            put(("llm", role, "model"), value)
    for tool in ("webcrack", "prettier", "retire"):
        value = env.get(f"EXTROSPECT_{tool.upper()}")
        if value:
            put(("tools", tool), value)
    if env.get("EXTROSPECT_EMBEDDING_MODEL"):
        put(("knowledge", "embedding_model"), env["EXTROSPECT_EMBEDDING_MODEL"])
    return data


def load_settings(path: Path | None = None, overrides: dict[str, Any] | None = None) -> Settings:
    """Build settings from defaults, the config file, env vars and ``overrides``."""
    data: dict[str, Any] = {}
    config_path = path or default_config_path()
    if config_path.is_file():
        with config_path.open("rb") as fh:
            data = tomllib.load(fh)
    data = _deep_merge(data, _env_overrides())
    if overrides:
        data = _deep_merge(data, overrides)
    return Settings.model_validate(data)


# --------------------------------------------------------------------------- template


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, Path):
        return _toml_value(str(value))
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, list | tuple):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        inner = ", ".join(f"{_toml_key(k)} = {_toml_value(v)}" for k, v in value.items())
        return "{ " + inner + " }" if inner else "{}"
    raise TypeError(f"unsupported TOML value: {value!r}")


def _toml_key(key: str) -> str:
    return key if key.replace("_", "").replace("-", "").isalnum() else _toml_value(key)


def default_config_toml(settings: Settings | None = None) -> str:
    """Render a TOML config file (commented header + all current values)."""
    settings = settings or Settings()
    payload = settings.model_dump(mode="json", exclude_none=True)
    lines = [
        "# Extrospect configuration.",
        "# Every key is optional; delete what you do not want to override.",
        "# API keys are NOT stored here: export ANTHROPIC_API_KEY / OPENAI_API_KEY / ... instead.",
        "",
    ]

    def emit(table: str, obj: dict[str, Any]) -> None:
        scalars = {k: v for k, v in obj.items() if not _is_table(v)}
        tables = {k: v for k, v in obj.items() if _is_table(v)}
        if table and scalars:
            lines.append(f"[{table}]")
        for key, value in scalars.items():
            lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
        if table and scalars:
            lines.append("")
        for key, value in tables.items():
            emit(f"{table}.{_toml_key(key)}" if table else _toml_key(key), value)

    top_scalars = {k: v for k, v in payload.items() if not _is_table(v)}
    for key, value in top_scalars.items():
        lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
    lines.append("")
    emit("", {k: v for k, v in payload.items() if _is_table(v)})
    return "\n".join(lines).rstrip() + "\n"


def _is_table(value: Any) -> bool:
    # Dicts of dicts become tables; small flat dicts are rendered inline.
    return isinstance(value, dict) and (
        not value or any(isinstance(v, dict) for v in value.values()) or len(value) > 6
    )


__all__ = [
    "APP_NAME",
    "PIPELINE_VERSION",
    "BudgetConfig",
    "FuseConfig",
    "KnowledgeConfig",
    "LlmConfig",
    "LlmModelConfig",
    "ModelPrice",
    "NetworkConfig",
    "PathsConfig",
    "RouterConfig",
    "Settings",
    "StaticConfig",
    "ToolsConfig",
    "default_config_path",
    "default_config_toml",
    "load_settings",
]
