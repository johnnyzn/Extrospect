"""Discover extensions installed in local Chromium-family browser profiles.

Reads ``Local State`` (profile list), ``Secure Preferences`` / ``Preferences``
(``extensions.settings``: enabled state, install location, unpacked paths) and scans
``<profile>/Extensions/<id>/<version>_0/``. Nothing is sent anywhere.

Preference field names differ across browser versions (``state`` vs
``disable_reasons``); both are handled. Set ``EXTROSPECT_BROWSER_ROOTS`` to
``name=path`` entries (``os.pathsep``-separated) to scan custom locations.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from extrospect.models import EXTENSION_ID_RE, ExtensionRef, InstalledExtension
from extrospect.static.manifest import load_json_file, summarize_manifest

_LINUX = {
    "chrome": [
        "~/.config/google-chrome",
        "~/.config/google-chrome-beta",
        "~/.config/google-chrome-unstable",
        "~/.var/app/com.google.Chrome/config/google-chrome",
    ],
    "chromium": [
        "~/.config/chromium",
        "~/snap/chromium/common/chromium",
        "~/.var/app/org.chromium.Chromium/config/chromium",
    ],
    "edge": [
        "~/.config/microsoft-edge",
        "~/.config/microsoft-edge-beta",
        "~/.config/microsoft-edge-dev",
        "~/.var/app/com.microsoft.Edge/config/microsoft-edge",
    ],
    "brave": [
        "~/.config/BraveSoftware/Brave-Browser",
        "~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
    ],
    "vivaldi": ["~/.config/vivaldi"],
}
_MACOS = {
    "chrome": [
        "~/Library/Application Support/Google/Chrome",
        "~/Library/Application Support/Google/Chrome Beta",
        "~/Library/Application Support/Google/Chrome Canary",
    ],
    "chromium": ["~/Library/Application Support/Chromium"],
    "edge": ["~/Library/Application Support/Microsoft Edge"],
    "brave": ["~/Library/Application Support/BraveSoftware/Brave-Browser"],
    "vivaldi": ["~/Library/Application Support/Vivaldi"],
}
_WINDOWS = {
    "chrome": [
        "%LOCALAPPDATA%/Google/Chrome/User Data",
        "%LOCALAPPDATA%/Google/Chrome Beta/User Data",
        "%LOCALAPPDATA%/Google/Chrome SxS/User Data",
    ],
    "chromium": ["%LOCALAPPDATA%/Chromium/User Data"],
    "edge": ["%LOCALAPPDATA%/Microsoft/Edge/User Data"],
    "brave": ["%LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data"],
    "vivaldi": ["%LOCALAPPDATA%/Vivaldi/User Data"],
}

# Manifest::Location enum (chrome/common/extensions/manifest.h)
LOCATIONS = {
    1: "webstore",  # INTERNAL: installed from a CRX (normally the Web Store)
    2: "external",
    3: "external",
    4: "unpacked",
    5: "component",
    6: "external",
    7: "policy",
    8: "command_line",
    9: "policy",
    10: "component",
}
# Built-in component extensions that are not user-installed.
COMPONENT_IDS = {
    "nmmhkkegccagdldgiimedpiccmgmieda",  # Chrome Web Store Payments
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm",  # Chrome Media Router
    "mhjfbmdgcfjbbpaeojofohoefgiehjai",  # Chrome PDF Viewer
    "ahfgeienlihckogmohjhadlkjgocpleb",  # Web Store app
    "kmendfapggjehodndflmmgagdbamhnfd",  # CryptoTokenExtension
    "neajdppkdcdipfabeoofebfddakdcjhd",  # Google Network Speech
    "nkeimhogjdpnpccoofpliimaahmaaome",  # Google Hangouts
}
_VERSION_DIR_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:_\d+)?$")


@dataclass
class BrowserRoot:
    browser: str
    path: Path


def default_roots() -> list[BrowserRoot]:
    env = os.environ.get("EXTROSPECT_BROWSER_ROOTS")
    if env:
        roots = []
        for item in env.split(os.pathsep):
            if not item.strip():
                continue
            name, sep, path = item.partition("=")
            if not sep:
                name, path = "chromium", item
            roots.append(BrowserRoot(name.strip() or "chromium", Path(path).expanduser()))
        return roots
    table = _WINDOWS if sys.platform == "win32" else _MACOS if sys.platform == "darwin" else _LINUX
    roots = []
    for browser, paths in table.items():
        for raw in paths:
            expanded = Path(os.path.expandvars(os.path.expanduser(raw)))
            if "%" not in str(expanded) and expanded.is_dir():
                roots.append(BrowserRoot(browser, expanded))
    return roots


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = load_json_file(path)
    except (OSError, ValueError, UnicodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _profiles(root: Path) -> list[tuple[str, str | None]]:
    """(profile directory, display name) pairs."""
    local_state = _read_json(root / "Local State")
    cache = (local_state.get("profile") or {}).get("info_cache") or {}
    profiles: dict[str, str | None] = {}
    if isinstance(cache, dict):
        for directory, info in cache.items():
            if (root / directory).is_dir():
                profiles[directory] = (info or {}).get("name") if isinstance(info, dict) else None
    for child in sorted(root.iterdir()) if root.is_dir() else []:
        if child.is_dir() and (child.name == "Default" or child.name.startswith("Profile ")):
            profiles.setdefault(child.name, None)
    return sorted(profiles.items(), key=lambda kv: (kv[0] != "Default", kv[0]))


def _extension_settings(profile_dir: Path) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for name in ("Preferences", "Secure Preferences"):
        prefs = _read_json(profile_dir / name)
        settings = (prefs.get("extensions") or {}).get("settings") or {}
        if isinstance(settings, dict):
            for ext_id, entry in settings.items():
                if isinstance(entry, dict):
                    merged.setdefault(ext_id, {}).update(entry)
    return merged


def _version_key(name: str) -> tuple[int, ...]:
    match = _VERSION_DIR_RE.match(name)
    if not match:
        return (-1,)
    return tuple(int(p) for p in match.group(1).split("."))


def _installed_dir(profile_dir: Path, ext_id: str, settings: dict[str, Any]) -> Path | None:
    location = settings.get("location")
    path_value = settings.get("path")
    if isinstance(path_value, str) and path_value:
        candidate = Path(path_value)
        if location == 4 or candidate.is_absolute():
            return candidate if (candidate / "manifest.json").is_file() else None
        candidate = profile_dir / "Extensions" / path_value
        if (candidate / "manifest.json").is_file():
            return candidate
    ext_root = profile_dir / "Extensions" / ext_id
    if not ext_root.is_dir():
        return None
    versions = [d for d in ext_root.iterdir() if d.is_dir() and (d / "manifest.json").is_file()]
    if not versions:
        return None
    return max(versions, key=lambda d: _version_key(d.name))


def _enabled(settings: dict[str, Any]) -> bool | None:
    if "disable_reasons" in settings:
        reasons = settings.get("disable_reasons")
        if isinstance(reasons, list):
            return len(reasons) == 0
        if isinstance(reasons, int):
            return reasons == 0
    if "state" in settings:
        return settings.get("state") == 1
    return None if not settings else True


def discover_extensions(
    roots: Iterable[BrowserRoot] | None = None,
    include_components: bool = False,
    ui_language: str | None = None,
) -> list[InstalledExtension]:
    found: list[InstalledExtension] = []
    for root in roots if roots is not None else default_roots():
        if not root.path.is_dir():
            continue
        for profile, profile_name in _profiles(root.path):
            profile_dir = root.path / profile
            settings_map = _extension_settings(profile_dir)
            ids = set(settings_map)
            ext_dir_root = profile_dir / "Extensions"
            if ext_dir_root.is_dir():
                ids |= {
                    d.name
                    for d in ext_dir_root.iterdir()
                    if d.is_dir() and EXTENSION_ID_RE.match(d.name)
                }
            for ext_id in sorted(ids):
                settings = settings_map.get(ext_id, {})
                location_code = settings.get("location")
                location = LOCATIONS.get(location_code) if isinstance(location_code, int) else None
                is_component = location == "component" or ext_id in COMPONENT_IDS
                if is_component and not include_components:
                    continue
                directory = _installed_dir(profile_dir, ext_id, settings)
                if directory is None:
                    continue
                raw = _read_json(directory / "manifest.json")
                if not raw:
                    continue
                summary = summarize_manifest(directory, raw, ui_language)
                if (
                    raw.get("theme") is not None
                    and not raw.get("background")
                    and not raw.get("content_scripts")
                ):
                    location = location or "theme"
                found.append(
                    InstalledExtension(
                        ref=ExtensionRef(
                            id=ext_id,
                            version=summary.version or None,
                            source="local",
                            path=directory,
                            browser=root.browser,
                            profile=profile,
                        ),
                        name=summary.name,
                        enabled=_enabled(settings),
                        install_location=location
                        or ("unpacked" if directory.parent.name != ext_id else None),
                        from_webstore=settings.get("from_webstore")
                        if isinstance(settings.get("from_webstore"), bool)
                        else None,
                        profile_name=profile_name,
                        manifest_version=summary.manifest_version,
                    )
                )
    found.sort(key=lambda e: (e.ref.browser or "", e.ref.profile or "", e.name.lower()))
    return found


def find_installed(
    ext_id: str, profile: str | None = None, browser: str | None = None
) -> InstalledExtension | None:
    for ext in discover_extensions(include_components=True):
        if ext.ref.id != ext_id:
            continue
        if profile and ext.ref.profile != profile:
            continue
        if browser and ext.ref.browser != browser:
            continue
        return ext
    return None


__all__ = [
    "COMPONENT_IDS",
    "LOCATIONS",
    "BrowserRoot",
    "default_roots",
    "discover_extensions",
    "find_installed",
]
