"""Build a fake Chromium profile with the fixture extensions "installed" (unpacked).

Lets you try the CLI or the MCP server end to end without installing anything into a
real browser. Extensions are copied under neutral folder names so a model cannot guess
labels from paths. Point Extrospect at it with ``EXTROSPECT_BROWSER_ROOTS``:

    uv run python scripts/make_demo_profile.py
    EXTROSPECT_BROWSER_ROOTS="chromium=$HOME/.cache/extrospect-demo-profile" uv run extrospect scan --local
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

from extrospect.static.manifest import id_from_path, load_manifest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "extensions"


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "extension"


def build(out: Path) -> list[tuple[str, str, Path]]:
    if out.exists():
        shutil.rmtree(out)
    profile = out / "Default"
    unpacked_root = out / "unpacked"
    profile.mkdir(parents=True)
    settings: dict[str, dict] = {}
    installed: list[tuple[str, str, Path]] = []
    for fixture in sorted(p for p in FIXTURES.iterdir() if (p / "manifest.json").is_file()):
        manifest, _ = load_manifest(fixture, "en")
        target = unpacked_root / slug(manifest.name)
        shutil.copytree(fixture, target)
        ext_id = id_from_path(target)
        settings[ext_id] = {
            "location": 4,
            "path": str(target.resolve()),
            "disable_reasons": [],
            "from_webstore": False,
        }
        installed.append((ext_id, manifest.name, target))
    (out / "Local State").write_text(
        json.dumps({"profile": {"info_cache": {"Default": {"name": "Demo profile"}}}}),
        encoding="utf-8",
    )
    (profile / "Secure Preferences").write_text(
        json.dumps({"extensions": {"settings": settings}}), encoding="utf-8"
    )
    return installed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--out", type=Path, default=Path.home() / ".cache" / "extrospect-demo-profile"
    )
    args = parser.parse_args(argv)
    out = args.out.expanduser().resolve()
    for ext_id, name, _ in build(out):
        print(f"{ext_id}  {name}")
    print(f"\nEXTROSPECT_BROWSER_ROOTS=chromium={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
