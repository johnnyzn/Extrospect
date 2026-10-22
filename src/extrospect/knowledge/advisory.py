"""RAG-C: vulnerability advisories (summary, affected functions, exploitation conditions).

Lookup order: curated built-in table -> local cache -> GitHub Advisory Database API
(online; ``GITHUB_TOKEN`` raises the rate limit). Turns "the library has a CVE" into a
concrete reachability question for the investigator.
"""

from __future__ import annotations

import json
import os
import re
from functools import cache
from importlib import resources
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from extrospect.pipeline import Context

GITHUB_ADVISORIES = "https://api.github.com/advisories"
ADVISORY_TTL_S = 30 * 24 * 3600
_ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$", re.I)
_FUNCTION_HINT_RE = re.compile(
    r"`([A-Za-z_$][\w$]*(?:\.[\w$]+)*(?:\(\))?)`|\b([A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*)\(\)"
)


@cache
def builtin_advisories() -> dict[str, dict[str, Any]]:
    data = json.loads(
        resources.files("extrospect.data")
        .joinpath("advisories_builtin.json")
        .read_text(encoding="utf-8")
    )
    return {k.upper(): v for k, v in data.items() if not k.startswith("_")}


def _functions_from_text(text: str) -> list[str]:
    found = []
    for a, b in _FUNCTION_HINT_RE.findall(text or ""):
        name = a or b
        if name and name not in found and len(name) < 60:
            found.append(name)
    return found[:12]


def parse_github_advisory(item: dict[str, Any]) -> dict[str, Any]:
    functions: list[str] = []
    packages = []
    for vuln in item.get("vulnerabilities") or []:
        functions.extend(f for f in vuln.get("vulnerable_functions") or [] if f not in functions)
        package = (vuln.get("package") or {}).get("name")
        if package:
            packages.append(
                {
                    "package": package,
                    "vulnerable_range": vuln.get("vulnerable_version_range"),
                    "first_patched": vuln.get("first_patched_version"),
                }
            )
    description = item.get("description") or ""
    for name in _functions_from_text(description):
        if name not in functions:
            functions.append(name)
    cvss = item.get("cvss") or {}
    return {
        "id": item.get("cve_id") or item.get("ghsa_id"),
        "ghsa_id": item.get("ghsa_id"),
        "summary": item.get("summary"),
        "description": description[:2000],
        "severity": item.get("severity"),
        "cvss": cvss.get("score"),
        "packages": packages,
        "affected_functions": functions[:15],
        "references": list(item.get("references") or [])[:6],
        "source": "github-advisory-database",
    }


def get_advisory(advisory_id: str, ctx: Context, online: bool = True) -> dict[str, Any] | None:
    key = advisory_id.strip().upper()
    if not _ID_RE.match(key):
        return None
    builtin = builtin_advisories().get(key)
    cached = ctx.cache.get_kv("advisory", key)
    if cached:
        merged = dict(cached)
        if builtin:
            merged.setdefault("conditions", builtin.get("conditions"))
            for fn in builtin.get("affected_functions", []):
                if fn not in merged.setdefault("affected_functions", []):
                    merged["affected_functions"].append(fn)
        return merged
    result: dict[str, Any] | None = {"id": key, **builtin, "source": "builtin"} if builtin else None
    if not online or ctx.http.offline or not ctx.settings.network.advisories:
        return result
    params = {"cve_id": key} if key.startswith("CVE-") else {"ghsa_id": key}
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = ctx.http.get(GITHUB_ADVISORIES, params=params, headers=headers, retries=1)
    except Exception:
        return result
    if response.status_code != 200:
        return result
    items = response.json()
    if not items:
        ctx.cache.put_kv(
            "advisory",
            key,
            result or {"id": key, "summary": None, "source": "none"},
            ttl_s=ADVISORY_TTL_S,
        )
        return result
    parsed = parse_github_advisory(items[0])
    if builtin:
        parsed["conditions"] = builtin.get("conditions")
        for fn in builtin.get("affected_functions", []):
            if fn not in parsed["affected_functions"]:
                parsed["affected_functions"].append(fn)
    ctx.cache.put_kv("advisory", key, parsed, ttl_s=ADVISORY_TTL_S)
    return parsed


def build_advisories(ctx: Context, cves: list[str] | None = None, limit: int = 200) -> int:
    """Pre-fetch advisories (default: every CVE in the cached retire.js repository)."""
    if not cves:
        from extrospect.static.vulns import load_repository

        repository = load_repository(ctx.settings, ctx.http) or {}
        found: list[str] = []
        for lib in repository.values():
            if not isinstance(lib, dict):
                continue
            for vuln in lib.get("vulnerabilities") or []:
                for cve in (vuln.get("identifiers") or {}).get("CVE", []) or []:
                    if cve not in found:
                        found.append(cve)
        cves = found
    count = 0
    for cve in cves[:limit]:
        if get_advisory(cve, ctx) is not None:
            count += 1
    return count


__all__ = ["build_advisories", "builtin_advisories", "get_advisory", "parse_github_advisory"]
