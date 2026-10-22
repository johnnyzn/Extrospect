"""Content-Security-Policy rules for extension pages and sandbox pages."""

from __future__ import annotations

from typing import Any

from extrospect.models import CapabilityFactor, ManifestSummary

_KEYWORDS = {
    "'self'",
    "'none'",
    "'unsafe-eval'",
    "'unsafe-inline'",
    "'wasm-unsafe-eval'",
    "'wasm-eval'",
    "'strict-dynamic'",
    "'unsafe-hashes'",
    "'report-sample'",
}
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


def parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for chunk in policy.split(";"):
        tokens = chunk.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:  # first occurrence wins, as in browsers
            directives[name] = [t.lower() if t.startswith("'") else t for t in tokens[1:]]
    return directives


def _script_sources(directives: dict[str, list[str]]) -> list[str]:
    for key in ("script-src", "script-src-elem", "default-src"):
        if key in directives:
            return directives[key]
    return []


def remote_sources(sources: list[str]) -> list[str]:
    remote = []
    for src in sources:
        low = src.lower()
        if low in _KEYWORDS or low.startswith(("'sha256-", "'sha384-", "'sha512-", "'nonce-")):
            continue
        if any(h in low for h in _LOCAL_HOSTS):
            continue
        if low in {"blob:", "filesystem:", "chrome-extension:", "'self'"}:
            continue
        remote.append(src)
    return remote


def _policy_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def analyze_csp(manifest: ManifestSummary) -> list[CapabilityFactor]:
    """Return capability factors derived from the manifest CSP (empty = default policy)."""
    factors: list[CapabilityFactor] = []
    csp = manifest.csp
    if csp is None:
        return factors

    pages_policy: str | None
    sandbox_policy: str | None
    if isinstance(csp, str):
        pages_policy, sandbox_policy = csp, None
    else:
        pages_policy = _policy_text(csp.get("extension_pages")) or _policy_text(
            csp.get("content_security_policy")
        )
        sandbox_policy = _policy_text(csp.get("sandbox"))

    if pages_policy:
        sources = _script_sources(parse_csp(pages_policy))
        if manifest.manifest_version <= 2:
            remote = remote_sources(sources)
            if remote:
                factors.append(
                    CapabilityFactor(
                        code="CSP_REMOTE_SCRIPT",
                        kind="csp",
                        weight=0.7,
                        params={"sources": " ".join(remote[:5])},
                    )
                )
            if "'unsafe-eval'" in sources:
                factors.append(CapabilityFactor(code="CSP_UNSAFE_EVAL", kind="csp", weight=0.7))
            if "'unsafe-inline'" in sources:
                factors.append(CapabilityFactor(code="CSP_UNSAFE_INLINE", kind="csp", weight=0.1))
        if "'wasm-unsafe-eval'" in sources or "'wasm-eval'" in sources:
            factors.append(CapabilityFactor(code="CSP_WASM_UNSAFE_EVAL", kind="csp", weight=0.1))

    if sandbox_policy:
        sources = _script_sources(parse_csp(sandbox_policy))
        if "'unsafe-eval'" in sources:
            factors.append(CapabilityFactor(code="CSP_SANDBOX_UNSAFE_EVAL", kind="csp", weight=0.4))
        remote = remote_sources(sources)
        if remote:
            factors.append(
                CapabilityFactor(
                    code="CSP_SANDBOX_REMOTE_SCRIPT",
                    kind="csp",
                    weight=0.4,
                    params={"sources": " ".join(remote[:5])},
                )
            )
    return factors


__all__ = ["analyze_csp", "parse_csp", "remote_sources"]
