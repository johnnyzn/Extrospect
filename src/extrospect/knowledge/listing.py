"""RAG-A: what an extension *declares* - Chrome Web Store listing and privacy disclosures.

The store page is parsed by its visible text labels (Version, Updated, Developer,
Website, Email, ratings, users, data-handling disclosures) rather than by CSS classes,
which change often. Everything here is optional: on any failure the analysis falls back
to the manifest description (``listing_from_manifest``). Results are cached for
``knowledge.listing_ttl_days``. An optional small-model pass extracts the declared
purpose / data types / first-party domains from the text (Engine mode).
"""

from __future__ import annotations

import contextlib
import html as html_lib
import re
from typing import TYPE_CHECKING, Any

from extrospect.knowledge.domains import first_party_domains
from extrospect.models import EXTENSION_ID_RE, ListingInfo, utcnow
from extrospect.util import one_line

if TYPE_CHECKING:
    from extrospect.llm.client import LLMClient
    from extrospect.pipeline import Context
    from extrospect.static.analyzer import StaticResult

STORE_URL = "https://chromewebstore.google.com/detail/{ext_id}?hl=en"
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_WEBSITE_RE = re.compile(
    r'<a [^>]*href="(https?://[^"]+)"[^>]*>(?:(?!</a>).){0,1500}?\bWebsite\s*</a>', re.S | re.I
)


def _text(fragment: str) -> str:
    return _WS_RE.sub(" ", html_lib.unescape(_TAG_RE.sub(" ", fragment))).strip()


def _number(value: str | None) -> int | None:
    if not value:
        return None
    value = value.replace(",", "").strip()
    match = re.fullmatch(r"([\d.]+)\s*([KkMm]?)", value)
    if not match:
        return None
    number = float(match.group(1))
    factor = {"k": 1_000, "m": 1_000_000}.get(match.group(2).lower(), 1)
    return int(number * factor)


def _label_value(page: str, label: str) -> str | None:
    match = re.search(
        rf">\s*{re.escape(label)}\s*</div>\s*<div[^>]*>(.*?)</div>", page, re.S | re.I
    )
    return _text(match.group(1)) if match else None


def parse_listing_html(page: str, ext_id: str) -> ListingInfo:
    info = ListingInfo(ext_id=ext_id, source="webstore", fetched_at=utcnow())
    title = re.search(r'<meta property="og:title" content="([^"]*)"', page)
    if title:
        info.name = html_lib.unescape(title.group(1)).removesuffix(" - Chrome Web Store").strip()
    description = re.search(
        r'<meta (?:name="description"|property="og:description") content="([^"]*)"', page
    )
    short = html_lib.unescape(description.group(1)).strip() if description else ""
    overview = re.search(r">\s*Overview\s*</h2>(.*?)</section>", page, re.S | re.I)
    long_text = _text(overview.group(1)) if overview else ""
    if not long_text and short:
        # The full description starts with the short summary inside a run of <p> elements.
        anchor = page.find("<p>" + html_lib.escape(short[:40], quote=False))
        if anchor >= 0:
            end = page.find("</div>", anchor)
            long_text = _text(page[anchor : end if end > 0 else anchor + 20_000])
    info.description = one_line(long_text or short, 4000) or None

    users = re.search(r"([\d,.]+[KkMm]?)\+?\s+users\b", page)
    info.users = _number(users.group(1)) if users else None
    rating = re.search(r"Average rating ([\d.]+) out of 5", page)
    info.rating = float(rating.group(1)) if rating else None
    rating_count = re.search(r">\s*([\d,.]+[KkMm]?)\s+ratings?\s*<", page)
    info.rating_count = _number(rating_count.group(1)) if rating_count else None
    info.version = _label_value(page, "Version")
    info.updated = _label_value(page, "Updated")
    info.featured = bool(re.search(r">\s*Featured\s*<", page))
    info.verified_publisher = bool(
        re.search(r"Established publisher|Verified publisher|>\s*Trader\s*<", page)
    )

    developer = re.search(r">\s*Developer\s*</div>(.*?)</li>", page, re.S | re.I)
    developer_html = developer.group(1) if developer else ""
    if developer_html:
        name = re.search(r"<div[^>]*>([^<]{2,200})(?:<br|</div>)", developer_html)
        if name:
            info.developer = _text(name.group(1))
        website = re.search(_WEBSITE_RE, developer_html)
        if website:
            info.website = html_lib.unescape(website.group(1))
    email = re.search(r">\s*Email\s*</summary>\s*<div[^>]*>([^<]+)</div>", page, re.I)
    developer_email = _text(email.group(1)) if email else None
    if not info.website:
        website = re.search(_WEBSITE_RE, page)
        if website:
            info.website = html_lib.unescape(website.group(1))
    privacy = re.search(r'href="(https?://[^"]+)"[^>]*>[^<]*privacy policy', page, re.I)
    if privacy:
        info.privacy_policy_url = html_lib.unescape(privacy.group(1))

    handles = re.search(
        r"(?:handles|collects) the following:?\s*</[^>]+>\s*(.*?)</(?:ul|div)>", page, re.S | re.I
    )
    if handles:
        info.data_collected = [
            i
            for i in (_text(x) for x in re.findall(r"<li[^>]*>(.*?)</li>", handles.group(1), re.S))
            if i
        ][:20]
    elif re.search(r"will not collect or use your data|does not collect", page, re.I):
        info.data_collected = []

    info.declared_purpose = one_line(short or long_text, 300) or None
    info.first_party_domains = sorted(
        first_party_domains([info.website, info.privacy_policy_url], [developer_email])
    )
    return info


def listing_from_manifest(static: StaticResult) -> ListingInfo:
    manifest = static.manifest
    return ListingInfo(
        ext_id=static.ref.id,
        name=manifest.name,
        description=manifest.description or None,
        website=manifest.homepage_url,
        version=manifest.version,
        declared_purpose=one_line(manifest.description, 300) or None,
        first_party_domains=sorted(static.first_party),
        source="manifest",
        fetched_at=utcnow(),
    )


LISTING_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "report_listing",
        "description": "Structured facts extracted from the listing.",
        "parameters": {
            "type": "object",
            "properties": {
                "declared_purpose": {"type": "string"},
                "data_collected": {"type": "array", "items": {"type": "string"}},
                "first_party_domains": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["declared_purpose", "data_collected", "first_party_domains"],
        },
    },
}


def extract_with_llm(info: ListingInfo, client: LLMClient, language: str) -> ListingInfo:
    """Small-model extraction of purpose / data types / first-party domains."""
    from extrospect.i18n import language_name
    from extrospect.llm.prompts import load_prompt
    from extrospect.llm.sanitize import wrap_untrusted_text

    prompt = load_prompt("listing_extract")
    body = "\n".join(
        f"{k}: {v}"
        for k, v in {
            "name": info.name,
            "developer": info.developer,
            "website": info.website,
            "privacy_policy_url": info.privacy_policy_url,
            "data disclosures": ", ".join(info.data_collected),
            "description": info.description,
        }.items()
        if v
    )
    messages = [
        {"role": "system", "content": prompt.render(language=language_name(language))},
        {"role": "user", "content": wrap_untrusted_text(body, "listing")},
    ]
    response = client.complete(
        "extractor", messages, tools=[LISTING_TOOL], span="listing", prompt_version=prompt.version
    )
    call = next((c for c in response.tool_calls if c.name == "report_listing"), None)
    if call is None:
        return info
    args = call.arguments
    updated = info.model_copy()
    if isinstance(args.get("declared_purpose"), str) and args["declared_purpose"].strip():
        updated.declared_purpose = one_line(args["declared_purpose"], 300)
    if isinstance(args.get("data_collected"), list) and not info.data_collected:
        updated.data_collected = [str(x) for x in args["data_collected"]][:20]
    extra = first_party_domains([str(d) for d in args.get("first_party_domains") or []])
    # Model-suggested domains only count when they match the developer's own website/email.
    trusted = set(info.first_party_domains)
    updated.first_party_domains = sorted(
        trusted | {d for d in extra if d in trusted or not trusted}
    )
    return updated


def get_listing(
    ext_id: str,
    ctx: Context,
    refresh: bool = False,
    client: LLMClient | None = None,
) -> ListingInfo | None:
    """Fetch (or load from cache) the store listing summary of ``ext_id``."""
    if not EXTENSION_ID_RE.match(ext_id):
        return None
    ttl = ctx.settings.knowledge.listing_ttl_days * 24 * 3600
    if not refresh:
        cached = ctx.cache.get_kv("listing", ext_id)
        if cached:
            info = ListingInfo.model_validate(cached)
            info.source = "cache"
            return info
    if ctx.http.offline or not ctx.settings.network.fetch_listing:
        return None
    response = ctx.http.get(
        STORE_URL.format(ext_id=ext_id),
        rate_key="chrome-webstore",
        per_second=ctx.settings.network.webstore_requests_per_s,
    )
    if response.status_code == 404:
        ctx.cache.put_kv("listing", ext_id, None, ttl_s=24 * 3600)
        return None
    response.raise_for_status()
    info = parse_listing_html(response.text, ext_id)
    if client is not None:
        with contextlib.suppress(Exception):
            info = extract_with_llm(info, client, ctx.language)
    ctx.cache.put_kv("listing", ext_id, info.model_dump(mode="json"), ttl_s=ttl)
    return info


__all__ = [
    "LISTING_TOOL",
    "extract_with_llm",
    "get_listing",
    "listing_from_manifest",
    "parse_listing_html",
]
