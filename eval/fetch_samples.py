"""Download evaluation samples (current store versions) and record availability.

The Chrome Web Store only serves the *current* version of *listed* extensions, so most
known-malicious ids are gone - this script measures exactly how many can still be
fetched (roadmap M0 risk) and writes ``<out>/availability.jsonl``.

Samples obtained elsewhere (research archives) can be imported with ``--import-dir``:
files or directories whose name starts with the 32-letter extension id.

    uv run python eval/fetch_samples.py --dataset eval/datasets/seed.jsonl --label benign --limit 20
    uv run python eval/fetch_samples.py --dataset eval/datasets/seed.jsonl --import-dir ~/malware-archive
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

from extrospect.acquire.crx_download import DownloadError, ExtensionUnavailable, download_crx
from extrospect.acquire.unpack import unpack_file
from extrospect.config import load_settings
from extrospect.evaluation import DatasetRow, load_dataset
from extrospect.http import HttpClient
from extrospect.models import EXTENSION_ID_RE, utcnow

ROOT = Path(__file__).resolve().parent.parent


def import_local(rows: list[DatasetRow], source: Path, out: Path) -> int:
    ids = {r.id for r in rows}
    count = 0
    for entry in sorted(source.iterdir()):
        ext_id = entry.name[:32]
        if ext_id not in ids or not EXTENSION_ID_RE.match(ext_id):
            continue
        if entry.is_dir():
            target = out / ext_id
            if not target.exists():
                shutil.copytree(entry, target)
                count += 1
        elif entry.suffix.lower() in {".crx", ".zip"}:
            target = out / f"{ext_id}{entry.suffix.lower()}"
            if not target.exists():
                shutil.copy2(entry, target)
                count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset", type=Path, default=ROOT / "eval/datasets/seed.jsonl")
    parser.add_argument("--out", type=Path, default=ROOT / "eval/samples")
    parser.add_argument(
        "--label", choices=["benign", "malicious"], help="Only rows with this label."
    )
    parser.add_argument("--split", default="all")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument(
        "--unpack", action="store_true", help="Also unpack each CRX into <out>/<id>/."
    )
    parser.add_argument(
        "--import-dir", type=Path, help="Import local archives instead of downloading."
    )
    args = parser.parse_args(argv)

    rows = [r for r in load_dataset(args.dataset) if EXTENSION_ID_RE.match(r.id)]
    if args.label:
        rows = [r for r in rows if r.label == args.label]
    if args.split != "all":
        rows = [r for r in rows if r.split == args.split]
    if args.limit:
        rows = rows[: args.limit]
    args.out.mkdir(parents=True, exist_ok=True)

    if args.import_dir:
        print(f"imported {import_local(rows, args.import_dir, args.out)} sample(s)")
        return 0

    settings = load_settings()
    settings.ensure_dirs()
    availability = args.out / "availability.jsonl"
    stats: Counter[tuple[str, bool]] = Counter()
    with HttpClient(settings.network) as http, availability.open("a", encoding="utf-8") as log:
        for row in rows:
            target = args.out / f"{row.id}.crx"
            record: dict = {"id": row.id, "label": row.label, "fetched_at": utcnow().isoformat()}
            if target.exists():
                record.update(available=True, cached=True)
            else:
                try:
                    result = download_crx(row.id, settings, http, dest_dir=args.out)
                    result.path.replace(target)
                    record.update(available=True, sha256=result.sha256, size=result.size)
                except ExtensionUnavailable as exc:
                    record.update(available=False, error=str(exc))
                except (DownloadError, OSError) as exc:
                    record.update(available=False, error=f"{type(exc).__name__}: {exc}")
            if record.get("available") and args.unpack and not (args.out / row.id).exists():
                try:
                    unpack_file(target, args.out / row.id)
                except Exception as exc:
                    record["unpack_error"] = str(exc)
            stats[(row.label, bool(record.get("available")))] += 1
            log.write(json.dumps(record, ensure_ascii=False) + "\n")
            print(
                f"{row.id} {row.label:9s} {'ok' if record.get('available') else 'unavailable'}",
                file=sys.stderr,
            )
    for label in ("malicious", "benign"):
        total = stats[(label, True)] + stats[(label, False)]
        if total:
            print(f"{label}: {stats[(label, True)]}/{total} available")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
