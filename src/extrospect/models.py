"""All pydantic data models shared across the pipeline, CLI, MCP server and evaluation.

Models that the LLM produces (``TriageResult``, ``Evidence``, ``Verdict``) are lenient:
they ignore unknown fields and coerce/clamp values, because model output is untrusted
input that must be validated but should not crash the pipeline on cosmetic issues.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")

Source = Literal["local", "webstore", "file"]
ContextKind = Literal["background", "content_script", "page", "unknown"]
RiskLevel = Literal["benign", "low", "medium", "high", "critical"]
VerdictLabel = Literal["benign", "suspicious", "malicious"]
Reachability = Literal["yes", "no", "unknown"]
TriageCategory = Literal[
    "benign", "tracking", "exfiltration", "injection", "hijack", "remote_control", "unclear"
]
SinkGroup = Literal["source", "exfil", "dynamic_code", "hijack", "suspicious", "surface"]
AnalysisMode = Literal["static", "engine", "host"]
VerdictSource = Literal["engine", "host", "lightweight", "static"]

RISK_LEVELS: tuple[RiskLevel, ...] = ("benign", "low", "medium", "high", "critical")
TRIAGE_CATEGORIES: tuple[str, ...] = (
    "benign",
    "tracking",
    "exfiltration",
    "injection",
    "hijack",
    "remote_control",
    "unclear",
)


def utcnow() -> datetime:
    return datetime.now(UTC)


def _clamp01(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number != number:  # NaN
        return 0.0
    if number > 1.0 and number <= 100.0:
        # Models occasionally answer in percent.
        number = number / 100.0
    return max(0.0, min(1.0, number))


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


# --------------------------------------------------------------------------- acquire


class ExtensionRef(_Model):
    """Identity of an extension being analysed."""

    id: str
    version: str | None = None
    source: Source
    path: Path | None = None  # unpacked directory on disk
    browser: str | None = None  # chrome / edge / brave / chromium
    profile: str | None = None  # profile directory name, e.g. "Default", "Profile 1"

    @property
    def is_valid_id(self) -> bool:
        return bool(EXTENSION_ID_RE.match(self.id))


class InstalledExtension(_Model):
    """One extension discovered in a local browser profile."""

    ref: ExtensionRef
    name: str
    enabled: bool | None = None
    install_location: str | None = None  # webstore / unpacked / policy / external / component
    from_webstore: bool | None = None
    profile_name: str | None = None  # human readable profile name from "Local State"
    manifest_version: int | None = None


# --------------------------------------------------------------------------- static


class ManifestSummary(_Model):
    name: str
    description: str = ""
    version: str = ""
    manifest_version: int = 2
    default_locale: str | None = None
    permissions: list[str] = Field(default_factory=list)
    optional_permissions: list[str] = Field(default_factory=list)
    host_permissions: list[str] = Field(default_factory=list)
    optional_host_permissions: list[str] = Field(default_factory=list)
    content_scripts: list[dict[str, Any]] = Field(default_factory=list)
    csp: dict[str, Any] | str | None = None
    web_accessible_resources: list[dict[str, Any]] = Field(default_factory=list)
    externally_connectable: dict[str, Any] | None = None
    update_url: str | None = None
    background: dict[str, Any] | None = None
    homepage_url: str | None = None
    author: str | None = None
    chrome_settings_overrides: dict[str, Any] | None = None
    chrome_url_overrides: dict[str, Any] | None = None
    declarative_net_request: dict[str, Any] | None = None
    sandbox_pages: list[str] = Field(default_factory=list)
    pages: dict[str, str] = Field(default_factory=dict)  # role -> html file (popup, options...)
    has_key: bool = False
    minimum_chrome_version: str | None = None
    oauth2_scopes: list[str] = Field(default_factory=list)
    name_raw: str | None = None  # original value, e.g. "__MSG_appName__"


class CapabilityFactor(_Model):
    """One reason contributing to the capability score ``A``."""

    code: str  # e.g. "PERM", "BROAD_HOST", "COMBO_BROAD_HOST_SENSITIVE", "CSP_MV2_UNSAFE_EVAL"
    kind: Literal["permission", "host", "combo", "csp", "surface", "override"]
    weight: float
    params: dict[str, Any] = Field(default_factory=dict)
    optional: bool = False


class CapabilityProfile(_Model):
    """The ``A`` (ability) dimension: what the extension *could* do."""

    score: float  # 0-1
    flags: list[str] = Field(default_factory=list)
    explanation: list[str] = Field(default_factory=list)
    factors: list[CapabilityFactor] = Field(default_factory=list)
    max_item: float = 0.0
    combo_count: int = 0
    broad_host: bool = False


class VulnFinding(_Model):
    library: str
    version: str
    cve: str  # primary identifier (CVE, GHSA or a retire.js summary id)
    identifiers: list[str] = Field(default_factory=list)
    severity: str | None = None
    summary: str | None = None
    file: str | None = None
    epss: float | None = None  # exploitation probability (0-1)
    epss_percentile: float | None = None  # percentile among all CVEs (0-1)
    cvss: float | None = None
    reachable: Reachability = "unknown"
    reachability_evidence: str | None = None
    info: list[str] = Field(default_factory=list)
    affected_functions: list[str] = Field(default_factory=list)


class Sink(_Model):
    """A security-relevant API use found by the AST scan."""

    kind: str  # "cookie_read", "network_exfil", "dynamic_code", ...
    group: SinkGroup
    api: str  # normalised API, e.g. "chrome.cookies.getAll"
    file: str
    line: int
    column: int = 0
    end_line: int | None = None
    snippet: str = ""
    weight: float = 0.0  # danger used for ranking (0-1)
    function: str | None = None  # enclosing function (best effort)
    in_library: bool = False
    detail: str | None = None


class CodeSlice(_Model):
    """A focused piece of code around one or more sinks, ready for the LLM."""

    slice_id: str  # sha256 of (context + sanitised code), truncated
    file: str
    start_line: int
    end_line: int
    code: str  # sanitised code (comments stripped, long strings elided)
    line_map: list[int] = Field(default_factory=list)  # code line index -> file line (0 = marker)
    sinks: list[Sink] = Field(default_factory=list)
    context: ContextKind = "unknown"
    segments: list[tuple[int, int]] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)
    danger: float = 0.0
    tokens: int = 0


class Endpoint(_Model):
    """A remote URL/host referenced in code (string literals)."""

    url: str
    host: str
    registrable_domain: str
    file: str
    line: int
    first_party: bool | None = None
    category: str | None = None


class LibraryInfo(_Model):
    file: str
    name: str
    version: str | None = None
    method: str  # retire / banner / filename / hash / path
    stripped: bool = True
    note: str | None = None


class CodeStats(_Model):
    js_files: int = 0
    html_files: int = 0
    total_bytes: int = 0
    total_lines: int = 0
    analyzed_bytes: int = 0  # after library stripping
    analyzed_lines: int = 0
    stripped_files: int = 0
    minified_files: int = 0
    formatted_files: int = 0
    deobfuscated_files: int = 0
    unpacked_modules: int = 0
    wasm_files: int = 0
    parse_errors: int = 0
    obfuscation_score: float = 0.0  # 0-1 heuristic


class InjectionAttempt(_Model):
    """Text in code that addresses an AI/auditor - itself a strong red flag."""

    file: str
    line: int
    text: str
    pattern: str


class Notice(_Model):
    """A localisable warning/info message: rendered via ``t('notice.<code>', **params)``."""

    code: str
    params: dict[str, Any] = Field(default_factory=dict)
    level: Literal["info", "warning", "error"] = "warning"


# --------------------------------------------------------------------------- LLM


class TriageResult(_Model):
    slice_id: str
    behavior: str = ""
    data_flow: str | None = None
    suspicion: float = 0.0
    evidence_lines: list[int] = Field(default_factory=list)
    category: TriageCategory = "unclear"
    cached: bool = False

    @field_validator("suspicion", mode="before")
    @classmethod
    def _clamp_suspicion(cls, value: Any) -> float:
        return _clamp01(value)

    @field_validator("category", mode="before")
    @classmethod
    def _normalise_category(cls, value: Any) -> str:
        text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
        return text if text in TRIAGE_CATEGORIES else "unclear"

    @field_validator("evidence_lines", mode="before")
    @classmethod
    def _coerce_lines(cls, value: Any) -> list[int]:
        if value is None:
            return []
        if isinstance(value, int | str):
            value = [value]
        lines: list[int] = []
        for item in value:
            try:
                lines.append(int(item))
            except (TypeError, ValueError):
                continue
        return lines


class Evidence(_Model):
    claim: str
    file: str
    lines: tuple[int, int]
    quote: str
    verified: bool | None = None  # set by the Verifier
    match: str | None = None  # how the quote matched: exact / normalized / sanitized

    @field_validator("lines", mode="before")
    @classmethod
    def _coerce_lines(cls, value: Any) -> tuple[int, int]:
        if isinstance(value, int | str):
            n = int(value)
            return (n, n)
        if isinstance(value, dict):
            start = int(value.get("start") or value.get("from") or 0)
            end = int(value.get("end") or value.get("to") or start)
            return (min(start, end), max(start, end))
        items = [int(v) for v in list(value)[:2]]
        if len(items) == 1:
            items.append(items[0])
        start, end = items
        return (min(start, end), max(start, end))


class Verdict(_Model):
    label: VerdictLabel
    malicious_prob: float
    purpose_consistent: bool | None = None
    attack_chain: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = 0.5
    needs_human_review: bool = False
    summary: str | None = None
    exfil_targets: list[str] = Field(default_factory=list)  # hosts receiving data
    source: VerdictSource = "engine"
    verified: bool = False  # passed the Verifier
    verifier_notes: list[Notice] = Field(default_factory=list)

    @field_validator("malicious_prob", "confidence", mode="before")
    @classmethod
    def _clamp(cls, value: Any) -> float:
        return _clamp01(value)

    @field_validator("label", mode="before")
    @classmethod
    def _normalise_label(cls, value: Any) -> str:
        text = str(value or "").strip().lower()
        if text in {"benign", "suspicious", "malicious"}:
            return text
        if text in {"safe", "clean", "ok", "legit", "legitimate"}:
            return "benign"
        if text in {"malware", "bad", "harmful"}:
            return "malicious"
        return "suspicious"

    @field_validator("purpose_consistent", mode="before")
    @classmethod
    def _coerce_bool(cls, value: Any) -> bool | None:
        if value is None or isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"true", "yes", "1"}:
            return True
        if text in {"false", "no", "0"}:
            return False
        return None


class ListingInfo(_Model):
    """RAG-A: what the store listing / privacy policy declares."""

    ext_id: str
    name: str | None = None
    description: str | None = None
    developer: str | None = None
    website: str | None = None
    privacy_policy_url: str | None = None
    users: int | None = None
    rating: float | None = None
    rating_count: int | None = None
    updated: str | None = None
    version: str | None = None
    verified_publisher: bool | None = None
    featured: bool | None = None
    declared_purpose: str | None = None
    data_collected: list[str] = Field(default_factory=list)
    first_party_domains: list[str] = Field(default_factory=list)
    source: Literal["webstore", "manifest", "cache"] = "manifest"
    fetched_at: datetime | None = None


class LlmUsage(_Model):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    calls: int = 0
    cost_usd: float = 0.0

    def add(self, other: LlmUsage) -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.calls += other.calls
        self.cost_usd += other.cost_usd


# --------------------------------------------------------------------------- scoring


class ScoreBreakdown(_Model):
    A: float = 0.0
    Ev: float = 0.0
    Em: float = 0.0
    E: float = 0.0
    raw: float = 0.0
    em_source: str = "none"  # llm / gbm / llm+gbm / rules / none
    llm_prob: float | None = None
    gbm_prob: float | None = None
    rules_prob: float | None = None
    hard_rules: list[str] = Field(default_factory=list)
    first_party_discount: bool = False
    one_way_kept_static: bool = False


class SliceSummary(_Model):
    slice_id: str
    file: str
    start_line: int
    end_line: int
    context: ContextKind
    danger: float
    sink_kinds: list[str]


class Report(_Model):
    ref: ExtensionRef
    manifest: ManifestSummary
    capability: CapabilityProfile
    vulns: list[VulnFinding] = Field(default_factory=list)
    verdict: Verdict | None = None
    score: int
    level: RiskLevel
    cost_usd: float = 0.0
    tokens: dict[str, int] = Field(default_factory=dict)
    pipeline_version: str
    trace_id: str
    mode: AnalysisMode = "static"
    language: str = "en"
    created_at: datetime = Field(default_factory=utcnow)
    breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    sink_counts: dict[str, int] = Field(default_factory=dict)
    top_sinks: list[Sink] = Field(default_factory=list)
    slices: list[SliceSummary] = Field(default_factory=list)
    triage: list[TriageResult] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    libraries: list[LibraryInfo] = Field(default_factory=list)
    stats: CodeStats = Field(default_factory=CodeStats)
    listing: ListingInfo | None = None
    injection_attempts: list[InjectionAttempt] = Field(default_factory=list)
    notices: list[Notice] = Field(default_factory=list)
    duration_s: float = 0.0

    @model_validator(mode="after")
    def _clamp_score(self) -> Report:
        self.score = max(0, min(100, int(self.score)))
        return self


__all__ = [
    "EXTENSION_ID_RE",
    "RISK_LEVELS",
    "TRIAGE_CATEGORIES",
    "AnalysisMode",
    "CapabilityFactor",
    "CapabilityProfile",
    "CodeSlice",
    "CodeStats",
    "ContextKind",
    "Endpoint",
    "Evidence",
    "ExtensionRef",
    "InjectionAttempt",
    "InstalledExtension",
    "LibraryInfo",
    "ListingInfo",
    "LlmUsage",
    "ManifestSummary",
    "Notice",
    "Reachability",
    "Report",
    "RiskLevel",
    "ScoreBreakdown",
    "Sink",
    "SinkGroup",
    "SliceSummary",
    "TriageCategory",
    "TriageResult",
    "Verdict",
    "VerdictLabel",
    "VulnFinding",
    "utcnow",
]
