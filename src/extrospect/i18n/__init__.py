"""Small message-catalog based internationalisation layer.

Catalogs live in ``locales/<code>.json`` as flat ``{"dotted.key": "Text with {param}"}``
maps. English (``en``) is the source of truth: every key must exist there. Other
catalogs may lag behind; a missing key falls back to English, then to the key itself.

The *current* language is stored in a :class:`contextvars.ContextVar`, so concurrent
MCP requests or threads can render in different languages without interfering.

Adding a language = dropping ``locales/<code>.json`` next to ``en.json``
(see ``docs/i18n.md``).
"""

from __future__ import annotations

import contextvars
import json
import locale
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from functools import cache
from importlib import resources
from typing import Any

DEFAULT_LANGUAGE = "en"

# Human-readable language names. They are used in LLM prompts ("write in ...") so any
# language the model knows can be requested, even without a UI catalog.
LANGUAGE_NAMES: dict[str, str] = {
    "en": "English",
    "zh-CN": "Simplified Chinese (简体中文)",
    "zh-TW": "Traditional Chinese (繁體中文)",
    "ja": "Japanese (日本語)",
    "ko": "Korean (한국어)",
    "es": "Spanish (Español)",
    "fr": "French (Français)",
    "de": "German (Deutsch)",
    "it": "Italian (Italiano)",
    "pt-BR": "Brazilian Portuguese (Português do Brasil)",
    "ru": "Russian (Русский)",
    "vi": "Vietnamese (Tiếng Việt)",
    "id": "Indonesian (Bahasa Indonesia)",
    "tr": "Turkish (Türkçe)",
    "ar": "Arabic (العربية)",
    "hi": "Hindi (हिन्दी)",
}

# Aliases that do not follow the simple ``lang-REGION`` normalisation.
_ALIASES: dict[str, str] = {
    "zh": "zh-CN",
    "zh-hans": "zh-CN",
    "zh-hans-cn": "zh-CN",
    "zh-sg": "zh-CN",
    "zh-hant": "zh-TW",
    "zh-hant-tw": "zh-TW",
    "zh-hk": "zh-TW",
    "zh-mo": "zh-TW",
    "pt": "pt-BR",
    "chinese": "zh-CN",
    "english": "en",
    "japanese": "ja",
}

_current: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "extrospect_language", default=None
)


class _SafeDict(dict[str, Any]):
    """``str.format_map`` helper that leaves unknown placeholders untouched."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def normalize_language(tag: str | None) -> str | None:
    """Normalise a locale/language tag to the canonical form used by catalogs.

    ``zh_CN.UTF-8`` -> ``zh-CN``, ``en_US`` -> ``en``, ``zh-Hant`` -> ``zh-TW``,
    ``ja_JP`` -> ``ja``. Returns ``None`` for empty, ``auto`` or POSIX/C locales.
    """
    if not tag:
        return None
    raw = tag.strip()
    if not raw or raw.lower() in {"auto", "c", "posix", "c.utf-8", "c.utf8"}:
        return None
    # Drop encoding and modifiers: "zh_CN.UTF-8@pinyin" -> "zh_CN"
    raw = raw.split(".", 1)[0].split("@", 1)[0]
    key = raw.replace("_", "-").lower()
    if key in _ALIASES:
        return _ALIASES[key]
    parts = key.split("-")
    base = parts[0]
    if not base.isalpha():
        return None
    if base == "zh":
        # Script/region decide between simplified and traditional Chinese.
        rest = set(parts[1:])
        if rest & {"tw", "hk", "mo", "hant"}:
            return "zh-TW"
        return "zh-CN"
    if base == "en":
        return "en"
    if len(parts) >= 2 and len(parts[-1]) == 2 and parts[-1].isalpha():
        candidate = f"{base}-{parts[-1].upper()}"
        if candidate in LANGUAGE_NAMES or _has_catalog(candidate):
            return candidate
    return base


def _system_language() -> str | None:
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(var)
        lang = normalize_language(value)
        if lang:
            return lang
    language_list = os.environ.get("LANGUAGE")
    if language_list:
        for item in language_list.split(":"):
            lang = normalize_language(item)
            if lang:
                return lang
    if sys.platform == "win32":  # pragma: no cover - platform specific
        try:
            import ctypes

            lang_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()  # type: ignore[attr-defined]
            lang = normalize_language(locale.windows_locale.get(lang_id))
            if lang:
                return lang
        except Exception:
            pass
    try:
        lang = normalize_language(locale.getlocale()[0])
        if lang:
            return lang
    except (ValueError, TypeError):
        pass
    return None


def resolve_language(explicit: str | None = None, configured: str | None = None) -> str:
    """Pick the UI language: explicit flag > ``EXTROSPECT_LANG`` > config > OS locale > en."""
    for candidate in (explicit, os.environ.get("EXTROSPECT_LANG"), configured):
        lang = normalize_language(candidate)
        if lang:
            return lang
    return _system_language() or DEFAULT_LANGUAGE


def set_language(lang: str | None) -> contextvars.Token[str | None]:
    """Set the language for the current context. Returns a token for ``reset``."""
    return _current.set(normalize_language(lang) or DEFAULT_LANGUAGE)


def get_language() -> str:
    """Return the language of the current context (defaults to OS-detected language)."""
    lang = _current.get()
    if lang is None:
        lang = resolve_language()
        _current.set(lang)
    return lang


@contextmanager
def use_language(lang: str | None) -> Iterator[str]:
    """Temporarily switch the current language."""
    token = set_language(lang)
    try:
        yield get_language()
    finally:
        _current.reset(token)


def language_name(lang: str | None = None) -> str:
    """Display name for a language code (used to steer LLM output language)."""
    code = normalize_language(lang) or get_language()
    if code in LANGUAGE_NAMES:
        return LANGUAGE_NAMES[code]
    base = code.split("-", 1)[0]
    return LANGUAGE_NAMES.get(base, code)


def _locales_dir() -> Any:
    return resources.files("extrospect.i18n").joinpath("locales")


@cache
def available_languages() -> tuple[str, ...]:
    """Languages that ship a UI catalog."""
    langs = []
    for entry in _locales_dir().iterdir():
        name = entry.name
        if name.endswith(".json"):
            langs.append(name[: -len(".json")])
    return tuple(sorted(langs, key=lambda c: (c != DEFAULT_LANGUAGE, c)))


def _has_catalog(lang: str) -> bool:
    return _locales_dir().joinpath(f"{lang}.json").is_file()


@cache
def load_catalog(lang: str) -> dict[str, str]:
    """Load one catalog (empty dict if the language has no catalog)."""
    path = _locales_dir().joinpath(f"{lang}.json")
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _fallback_chain(lang: str) -> list[str]:
    chain = [lang]
    base = lang.split("-", 1)[0]
    if base != lang:
        chain.append(base)
    if lang == "zh-TW":
        # Better a Simplified-Chinese string than English for a Traditional-Chinese reader.
        chain.append("zh-CN")
    if DEFAULT_LANGUAGE not in chain:
        chain.append(DEFAULT_LANGUAGE)
    return chain


def has_key(key: str, lang: str | None = None) -> bool:
    return any(key in load_catalog(code) for code in _fallback_chain(lang or DEFAULT_LANGUAGE))


def t(key: str, lang: str | None = None, /, **params: Any) -> str:
    """Translate ``key`` into ``lang`` (or the current language) and format ``params``."""
    code = normalize_language(lang) or get_language()
    for candidate in _fallback_chain(code):
        template = load_catalog(candidate).get(key)
        if template is not None:
            return template.format_map(_SafeDict(params)) if params else template
    return key.format_map(_SafeDict(params)) if params else key


def t_or(key: str, default: str, lang: str | None = None, /, **params: Any) -> str:
    """Like :func:`t` but returns ``default`` (formatted) when no catalog has the key."""
    code = normalize_language(lang) or get_language()
    for candidate in _fallback_chain(code):
        template = load_catalog(candidate).get(key)
        if template is not None:
            return template.format_map(_SafeDict(params))
    return default.format_map(_SafeDict(params))


__all__ = [
    "DEFAULT_LANGUAGE",
    "LANGUAGE_NAMES",
    "available_languages",
    "get_language",
    "has_key",
    "language_name",
    "load_catalog",
    "normalize_language",
    "resolve_language",
    "set_language",
    "t",
    "t_or",
    "use_language",
]
