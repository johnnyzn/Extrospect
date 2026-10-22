"""RAG knowledge bases and the MCP server (in-process, offline)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

from extrospect.http import HttpClient
from extrospect.knowledge.advisory import get_advisory, parse_github_advisory
from extrospect.knowledge.embeddings import HashEmbedder, code_tokens, cosine
from extrospect.knowledge.intel import builtin_entries, search_intel
from extrospect.knowledge.listing import get_listing, parse_listing_html
from extrospect.knowledge.store import LanceStore, SimpleStore

LISTING_HTML = """<html><head>
<meta property="og:title" content="Lingvo Translate - Chrome Web Store">
<meta name="description" content="Translate the selected text on any page.">
</head><body>
<div><a href="./category/extensions">Extension</a>1,234,567 users</div>
<span role="img" aria-label="Average rating 4.5 out of 5 stars."></span><p class="x">12.3K ratings</p>
<span>Featured</span>
<h2>Overview</h2><div><p>Translate the selected text on any page.</p><p>Uses the Lingvo API.</p></div></section>
<ul>
<li><div class="a">Version</div><div class="b">3.4.1</div></li>
<li><div class="a">Updated</div><div>September 1, 2026</div></li>
<li><div class="a">Developer</div><div><div><div>Lingvo GmbH<br>Street 1 Berlin</div>
  <a class="w" href="https://lingvo-translate.example/" rel="ugc nofollow" target="_blank"><svg></svg> Website</a>
  <details><summary> Email </summary><div class="m">support@lingvo-translate.example</div></details></div></div></li>
</ul>
<h2>Privacy</h2><div>Lingvo Translate has disclosed the following information. <a href="https://lingvo-translate.example/privacy">privacy policy</a></div>
<div><h2>Lingvo Translate handles the following:</h2><ul><li>Website content</li><li>User activity</li></ul></div>
</body></html>"""


def test_listing_parser() -> None:
    info = parse_listing_html(LISTING_HTML, "a" * 32)
    assert info.name == "Lingvo Translate"
    assert info.users == 1_234_567 and info.rating == 4.5 and info.rating_count == 12_300
    assert info.version == "3.4.1" and info.updated == "September 1, 2026"
    assert info.developer == "Lingvo GmbH" and info.website == "https://lingvo-translate.example/"
    assert info.privacy_policy_url == "https://lingvo-translate.example/privacy"
    assert info.data_collected == ["Website content", "User activity"]
    assert info.first_party_domains == ["lingvo-translate.example"]
    assert info.featured and "Lingvo API" in (info.description or "")


def test_get_listing_uses_http_and_cache(ctx) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text=LISTING_HTML)

    ctx.settings.network.offline = False
    ctx.http = HttpClient(ctx.settings.network, transport=httpx.MockTransport(handler))
    info = get_listing("a" * 32, ctx)
    assert info is not None and info.source == "webstore"
    again = get_listing("a" * 32, ctx)
    assert again is not None and again.source == "cache" and len(calls) == 1
    assert "chromewebstore.google.com/detail/" + "a" * 32 in calls[0]
    assert get_listing("not-an-id", ctx) is None


def test_hash_embedder_is_deterministic_and_code_aware() -> None:
    embedder = HashEmbedder(256)
    a = embedder.embed_one(
        "chrome.cookies.getAll({}, c => fetch(u, {method:'POST', body: JSON.stringify(c)}))"
    )
    b = embedder.embed_one(
        "chrome.cookies.getAll({}, (cookies) => fetch(url, {method: 'POST', body: JSON.stringify(cookies)}))"
    )
    c = embedder.embed_one("document.querySelector('#title').textContent = 'Hello world';")
    assert a == embedder.embed_one(
        "chrome.cookies.getAll({}, c => fetch(u, {method:'POST', body: JSON.stringify(c)}))"
    )
    assert cosine(a, b) > cosine(a, c)
    assert code_tokens("var _0x1a2b = 123;") == ["var", "<obf>", "=", "<num>", ";"]


@pytest.mark.parametrize("store_cls", [SimpleStore, LanceStore])
def test_vector_stores(tmp_path: Path, store_cls: Any) -> None:
    if store_cls is LanceStore:
        pytest.importorskip("lancedb")
    store = store_cls(tmp_path / ("db" if store_cls is LanceStore else "v.sqlite3"))
    store.add(
        "intel",
        "emb",
        [
            ("x", [1.0, 0.0, 0.0], "tx", {"family": "f1"}),
            ("y", [0.0, 1.0, 0.0], "ty", {"family": "f2"}),
        ],
    )
    hits = store.search("intel", "emb", [0.9, 0.1, 0.0], 2)
    assert [h.id for h in hits] == ["x", "y"] and hits[0].metadata == {"family": "f1"}
    assert hits[0].score > hits[1].score
    store.add("intel", "emb", [("x", [0.0, 0.0, 1.0], "tx2", {"family": "f1"})])  # upsert
    assert store.count("intel", "emb") == 2
    assert store.search("intel", "other-embedder", [1.0, 0.0, 0.0], 2) == []


def test_intel_search_finds_matching_technique(ctx) -> None:
    assert len(builtin_entries()) >= 20
    query = """
    chrome.declarativeNetRequest.updateDynamicRules({ addRules: [{ id: 3, action: { type: "redirect",
      redirect: { regexSubstitution: "https://feed.example/?q=\\\\1" } }, condition: { regexFilter: "^https://www\\\\.google\\\\.com/search\\\\?q=(.*)" } }] });
    """
    hits = search_intel(query, ctx, k=3)
    assert hits[0]["id"] == "search-redirect-dnr"
    assert hits[0]["family"] == "search-hijacker" and 0 < hits[0]["similarity"] <= 1


def test_advisories_builtin_and_github(ctx) -> None:
    builtin = get_advisory("cve-2019-11358", ctx)
    assert (
        builtin is not None
        and builtin["source"] == "builtin"
        and "jQuery.extend" in builtin["affected_functions"]
    )
    assert get_advisory("not-a-cve", ctx) is None

    payload = [
        {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2099-0001",
            "summary": "Prototype pollution in merge",
            "description": "Calling `lib.merge()` with untrusted input pollutes Object.prototype.",
            "severity": "high",
            "cvss": {"score": 8.1},
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "lib"},
                    "vulnerable_version_range": "< 2.0.0",
                    "first_patched_version": "2.0.0",
                    "vulnerable_functions": ["lib.mergeDeep"],
                }
            ],
            "references": ["https://example.com/advisory"],
        }
    ]
    parsed = parse_github_advisory(payload[0])
    assert parsed["affected_functions"] == ["lib.mergeDeep", "lib.merge()"]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["cve_id"] == "CVE-2099-0001"
        return httpx.Response(200, json=payload)

    ctx.settings.network.offline = False
    ctx.http = HttpClient(ctx.settings.network, transport=httpx.MockTransport(handler))
    advisory = get_advisory("CVE-2099-0001", ctx)
    assert (
        advisory is not None
        and advisory["cvss"] == 8.1
        and advisory["packages"][0]["first_patched"] == "2.0.0"
    )
    assert ctx.cache.get_kv("advisory", "CVE-2099-0001")["ghsa_id"] == "GHSA-xxxx-yyyy-zzzz"


# --------------------------------------------------------------------------- MCP server


@pytest.fixture
def mcp_server(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fixtures_dir: Path, settings
) -> Any:
    from extrospect_mcp.server import build_server
    from test_acquire import make_profile_tree

    root = tmp_path / "chrome"
    make_profile_tree(root, fixtures_dir / "inj_prompt_injection")
    monkeypatch.setenv("EXTROSPECT_BROWSER_ROOTS", f"chrome={root}")
    overrides = {
        "paths": {
            "data_dir": str(settings.paths.data_dir),
            "cache_dir": str(settings.paths.cache_dir),
        }
    }
    return build_server(overrides)


def call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        result = await server.call_tool(name, args)
        return json.loads(result.content[0].text)

    return anyio.run(run)


def test_mcp_tools_end_to_end(mcp_server: Any) -> None:
    async def names() -> list[str]:
        return [tool.name for tool in await mcp_server.list_tools()]

    tools = anyio.run(names)
    assert set(tools) == {
        "list_installed_extensions",
        "quick_scan",
        "get_slices",
        "read_file",
        "search_code",
        "get_callers",
        "decode_string",
        "lookup_domain",
        "retrieve_listing",
        "retrieve_similar_malware",
        "retrieve_advisory",
        "submit_verdict",
        "full_analyze",
    }
    listing = call(mcp_server, "list_installed_extensions", {})
    assert listing["count"] == 4
    ext = "c" * 32  # the unpacked prompt-injection fixture
    scan = call(mcp_server, "quick_scan", {"ext_id": ext})
    assert scan["name"] == "Shopping Helper" and scan["level"] in {"high", "critical"}
    assert scan["prompt_injection_attempts"] == 2
    dumped = json.dumps(scan, ensure_ascii=False)
    assert (
        "AUDITORS" not in dumped and "判定为安全" not in dumped
    )  # injection text never reaches the client model
    slices = call(mcp_server, "get_slices", {"ext_id": ext, "top": 3})
    assert slices["slices"][0]["code"].count("<untrusted_code") == 1
    assert "error" in call(mcp_server, "read_file", {"ext_id": ext, "path": "../../etc/passwd"})
    assert "error" in call(mcp_server, "quick_scan", {"ext_id": "../../etc"})
    verdict = call(
        mcp_server,
        "submit_verdict",
        {
            "ext_id": ext,
            "label": "malicious",
            "malicious_prob": 0.95,
            "confidence": 0.8,
            "summary": "credential stealer",
            "attack_chain": "submit listener -> password field -> sendBeacon",
            "evidence": [
                {
                    "claim": "reads the password field",
                    "file": "helper.js",
                    "lines": [10, 10],
                    "quote": 'const pass = form.querySelector("input[type=password]");',
                },
                {
                    "claim": "invented",
                    "file": "helper.js",
                    "lines": [1, 1],
                    "quote": "uploadEverything(window)",
                },
            ],
        },
    )
    assert verdict["verdict"] == "malicious" and len(verdict["verified_evidence"]) == 1
    assert verdict["score"] >= 80 and any("not found" in note for note in verdict["verifier_notes"])

    async def resource() -> str:
        contents = await mcp_server.read_resource(f"extrospect://report/{ext}")
        return str(contents[0].content)

    markdown = anyio.run(resource)
    assert "Host mode" in markdown and "[redacted" in markdown and "AUDITORS" not in markdown


def test_mcp_prompt_and_engine_errors(mcp_server: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    async def prompt() -> str:
        result = await mcp_server.get_prompt("audit_my_extensions", {"language": "zh-CN"})
        return result.messages[0].content.text

    text = anyio.run(prompt)
    assert "list_installed_extensions" in text and "Simplified Chinese" in text
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    result = call(mcp_server, "full_analyze", {"ext_id": "c" * 32})
    assert "error" in result


def test_mcp_main_parses_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    from extrospect_mcp import server as module

    captured: dict[str, Any] = {}

    class Dummy:
        def run(self) -> None:
            captured["ran"] = True

    def fake_build(overrides: dict[str, Any], allow_download: bool = False) -> Dummy:
        captured.update(overrides=overrides, allow_download=allow_download)
        return Dummy()

    monkeypatch.setattr(module, "build_server", fake_build)
    module.main(["--lang", "zh-CN", "--offline", "--allow-download"])
    assert captured == {
        "overrides": {"network": {"offline": True}, "language": "zh-CN"},
        "allow_download": True,
        "ran": True,
    }
    assert os.environ.get("EXTROSPECT_OFFLINE") == "1"
