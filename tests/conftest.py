"""Shared fixtures. Tests never touch the network and never call a real LLM."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from extrospect.config import Settings, load_settings
from extrospect.i18n import set_language

FIXTURES = Path(__file__).parent / "fixtures"
EXTENSIONS = FIXTURES / "extensions"
MALICIOUS = ["mal_cookie_exfil", "mal_search_hijack", "mal_remote_config", "inj_prompt_injection"]
BENIGN = ["benign_word_counter", "benign_translator", "benign_legacy_jquery"]


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in ("EXTROSPECT_LANG", "EXTROSPECT_CONFIG", "EXTROSPECT_BROWSER_ROOTS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("EXTROSPECT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("EXTROSPECT_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("EXTROSPECT_OFFLINE", "1")
    monkeypatch.setenv("EXTROSPECT_CONFIG", str(tmp_path / "no-config.toml"))
    set_language("en")


@pytest.fixture
def fixtures_dir() -> Path:
    return EXTENSIONS


@pytest.fixture
def retire_repo() -> dict:
    return json.loads((FIXTURES / "retire" / "jsrepository-mini.json").read_text(encoding="utf-8"))


@pytest.fixture
def settings(tmp_path: Path, retire_repo: dict) -> Settings:
    settings = load_settings(
        tmp_path / "no-config.toml",
        {
            "paths": {"data_dir": str(tmp_path / "data"), "cache_dir": str(tmp_path / "cache")},
            "network": {"offline": True},
            "tools": {
                "webcrack": "/nonexistent/webcrack",
                "prettier": "/nonexistent/prettier",
                "retire": "/nonexistent/retire",
            },
        },
    )
    settings.ensure_dirs()
    # Pretend the retire.js repository was downloaded earlier so the Python matcher runs offline.
    repo_path = settings.paths.cache_dir / "retire" / "jsrepository-v5.json"
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    repo_path.write_text(json.dumps(retire_repo), encoding="utf-8")
    return settings


@pytest.fixture
def ctx(settings: Settings) -> Iterator[object]:
    from extrospect.pipeline import Context

    context = Context.create(settings=settings, language="en")
    yield context
    context.close()


@pytest.fixture
def ext_copy(tmp_path: Path):
    """Copy a fixture extension into tmp so a test may modify it."""

    def _copy(name: str) -> Path:
        dest = tmp_path / "ext" / name
        shutil.copytree(EXTENSIONS / name, dest)
        return dest

    return _copy


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("EXTROSPECT_TEST_NETWORK") == "1":
        return
    skip = pytest.mark.skip(reason="network test (set EXTROSPECT_TEST_NETWORK=1)")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)
