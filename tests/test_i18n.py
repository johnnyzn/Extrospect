from __future__ import annotations

import ast
import json
import re
import string
from pathlib import Path

import pytest

from extrospect.i18n import (
    available_languages,
    language_name,
    load_catalog,
    normalize_language,
    resolve_language,
    t,
    use_language,
)
from extrospect.static import csp, permissions, sinks

SRC = Path(__file__).parent.parent / "src"
LOCALES = SRC / "extrospect" / "i18n" / "locales"


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("zh_CN.UTF-8", "zh-CN"),
        ("zh-Hans", "zh-CN"),
        ("zh", "zh-CN"),
        ("zh_TW", "zh-TW"),
        ("zh-HK", "zh-TW"),
        ("en_US.UTF-8", "en"),
        ("en-GB", "en"),
        ("ja_JP", "ja"),
        ("pt_BR", "pt-BR"),
        ("C", None),
        ("POSIX", None),
        ("auto", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_language(tag: str | None, expected: str | None) -> None:
    assert normalize_language(tag) == expected


def test_resolve_language_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LANG", "ja_JP.UTF-8")
    assert resolve_language() == "ja"
    monkeypatch.setenv("EXTROSPECT_LANG", "zh-CN")
    assert resolve_language() == "zh-CN"
    assert resolve_language("en") == "en"


def test_translation_and_fallback() -> None:
    assert t("level.high", "en") == "high"
    assert t("level.high", "zh-CN") == "高风险"
    # zh-TW has no catalog: falls back to Simplified Chinese before English.
    assert t("level.high", "zh-TW") == "高风险"
    # Unknown language falls back to English.
    assert t("level.high", "fr") == "high"
    assert t("no.such.key", "en") == "no.such.key"
    assert t("cli.score_line", "en", score=42) == "Risk 42/100"
    # Missing placeholders are left as-is rather than raising.
    assert "{score}" in t("cli.score_line", "en")
    with use_language("zh-CN"):
        assert t("label.malicious") == "恶意"
    assert t("label.malicious") == "malicious"


def test_language_names_for_prompts() -> None:
    assert "Chinese" in language_name("zh-CN")
    assert language_name("en") == "English"
    assert language_name("xx") == "xx"


def test_shipped_languages() -> None:
    langs = available_languages()
    assert langs[0] == "en"
    assert "zh-CN" in langs


def _placeholders(text: str) -> set[str]:
    return {field for _, field, _, _ in string.Formatter().parse(text) if field}


@pytest.mark.parametrize("lang", [lang for lang in available_languages() if lang != "en"])
def test_catalog_parity(lang: str) -> None:
    en = load_catalog("en")
    other = load_catalog(lang)
    assert set(en) - set(other) == set(), f"{lang} is missing keys"
    assert set(other) - set(en) == set(), f"{lang} has keys that English does not"
    for key, text in en.items():
        assert _placeholders(text) == _placeholders(other[key]), (
            f"placeholder mismatch for {key} in {lang}"
        )


def test_catalog_files_are_valid_json() -> None:
    for path in LOCALES.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert all(isinstance(v, str) for v in data.values())


def _constant_keys() -> set[str]:
    keys: set[str] = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"t", "t_or"}
            ) and (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                keys.add(node.args[0].value)
    return keys


def test_every_constant_key_exists_in_english() -> None:
    en = load_catalog("en")
    missing = sorted(k for k in _constant_keys() if k not in en)
    assert not missing, f"keys used in code but missing from en.json: {missing}"


def test_dynamic_key_families_exist() -> None:
    en = load_catalog("en")
    kinds = {rule.kind for rule in sinks.CALL_RULES.values()} | {
        rule.kind for _, _, rule in sinks.AFFIX_RULES
    }
    sink_src = Path(sinks.__file__).read_text(encoding="utf-8")
    kinds |= set(re.findall(r'_r\("([a-z_]+)"', sink_src))
    kinds |= set(re.findall(r'kind="([a-z_]+)"', sink_src))
    kinds |= {"prompt_injection", "page_storage_read"}
    assert not sorted(k for k in kinds if f"sink.{k}" not in en)

    cap_src = Path(permissions.__file__).read_text(encoding="utf-8") + Path(csp.__file__).read_text(
        encoding="utf-8"
    )
    codes = set(re.findall(r'code="([A-Z_]+)"', cap_src))
    assert codes and not sorted(c for c in codes if f"cap.{c}" not in en)

    notice_codes: set[str] = set()
    for path in SRC.rglob("*.py"):
        notice_codes |= set(
            re.findall(r'Notice\(\s*code="([a-z_]+)"', path.read_text(encoding="utf-8"))
        )
    assert not sorted(c for c in notice_codes if f"notice.{c}" not in en)
