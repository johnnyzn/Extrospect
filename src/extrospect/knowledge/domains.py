"""Domain helpers: well-known third-party categories and first-party matching."""

from __future__ import annotations

from collections.abc import Iterable

from extrospect.util import host_of, registrable_domain

# Registrable domain -> category. Deliberately small and conservative: it labels
# common infrastructure so the LLM and the report can tell "analytics SDK" from
# "unknown server", it never marks anything as safe by itself.
KNOWN_DOMAINS: dict[str, str] = {
    "google-analytics.com": "analytics",
    "googletagmanager.com": "analytics",
    "doubleclick.net": "advertising",
    "googlesyndication.com": "advertising",
    "googleadservices.com": "advertising",
    "amplitude.com": "analytics",
    "mixpanel.com": "analytics",
    "mxpnl.com": "analytics",
    "segment.io": "analytics",
    "segment.com": "analytics",
    "posthog.com": "analytics",
    "hotjar.com": "analytics",
    "fullstory.com": "analytics",
    "heap.io": "analytics",
    "heapanalytics.com": "analytics",
    "sentry.io": "error_reporting",
    "bugsnag.com": "error_reporting",
    "googleapis.com": "google_api",
    "gstatic.com": "cdn",
    "google.com": "google",
    "jsdelivr.net": "cdn",
    "unpkg.com": "cdn",
    "cloudflare.com": "cdn",
    "cdnjs.com": "cdn",
    "jquery.com": "cdn",
    "bootstrapcdn.com": "cdn",
    "fontawesome.com": "cdn",
    "firebaseio.com": "backend_platform",
    "firebaseapp.com": "backend_platform",
    "amazonaws.com": "cloud",
    "cloudfront.net": "cdn",
    "azurewebsites.net": "cloud",
    "herokuapp.com": "cloud",
    "workers.dev": "cloud",
    "facebook.com": "social",
    "facebook.net": "social",
    "twitter.com": "social",
    "x.com": "social",
    "github.com": "code_hosting",
    "githubusercontent.com": "code_hosting",
    "chromewebstore.google.com": "webstore",
    "chrome.google.com": "webstore",
    "openai.com": "ai_api",
    "anthropic.com": "ai_api",
    "ngrok.io": "tunnel",
    "ngrok-free.app": "tunnel",
    "pastebin.com": "paste_site",
    "telegram.org": "messaging",
    "discord.com": "messaging",
    "discordapp.com": "messaging",
}


def categorize_domain(domain: str) -> str | None:
    reg = registrable_domain(domain)
    return KNOWN_DOMAINS.get(reg) or KNOWN_DOMAINS.get(domain.lower())


def first_party_domains(urls: Iterable[str | None], emails: Iterable[str | None] = ()) -> set[str]:
    """Registrable domains of URLs (homepage, website, privacy policy) and emails."""
    domains: set[str] = set()
    for url in urls:
        if not url:
            continue
        host = host_of(url) if "://" in url else url.strip().lower()
        reg = registrable_domain(host)
        if reg and "." in reg:
            domains.add(reg)
    for email in emails:
        if email and "@" in email:
            reg = registrable_domain(email.rsplit("@", 1)[-1])
            if (
                reg
                and "." in reg
                and reg
                not in {
                    "gmail.com",
                    "outlook.com",
                    "hotmail.com",
                    "yahoo.com",
                    "qq.com",
                    "163.com",
                    "icloud.com",
                    "proton.me",
                    "protonmail.com",
                }
            ):
                domains.add(reg)
    return domains


def is_first_party(domain: str, first_party: set[str]) -> bool | None:
    if not first_party:
        return None
    return registrable_domain(domain) in first_party


__all__ = ["KNOWN_DOMAINS", "categorize_domain", "first_party_domains", "is_first_party"]
