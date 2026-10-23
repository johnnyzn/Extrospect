"""Evaluate Host mode: a Claude Code model drives the Extrospect MCP server.

Every sample runs in a fresh, non-interactive ``claude -p`` session that may only use the
Extrospect tools. The server reads the sample from the evaluation workspace (CRX files
are served as earlier downloads, sample folders are "installed" unpacked under a neutral
folder name) and never downloads anything itself; the final score is read back from its
report store. Runs spend the usage of the account the Claude CLI is logged in with
(subscription or API), so ``--yes`` is required.

    uv run python eval/run_host_eval.py --split test --model sonnet --yes
    uv run python eval/run_host_eval.py --model sonnet --report

Results are appended to ``<work-dir>/results.jsonl``. A rerun skips samples that already
have a result, so a run stopped by a usage limit or ``--deadline`` can be resumed. When
the CLI reports a usage limit, the run waits for the reset (unless that is past the
deadline) and retries the sample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from extrospect.evaluation import (
    DEFAULT_THRESHOLD,
    SampleResult,
    compute_metrics,
    load_dataset,
    resolve_sample,
)
from extrospect.static.manifest import id_from_path

ROOT = Path(__file__).resolve().parent.parent
PROMPT = (
    "Use the Extrospect tools to analyze the Chrome extension {ext_id}. It is already "
    "available to the server: call quick_scan with just its id. Investigate the riskiest "
    "code, check the store listing, then call submit_verdict. End your answer with one "
    "line: VERDICT <benign|suspicious|malicious> <score>."
)
DISALLOWED = "Bash,Read,Grep,Glob,Edit,Write,NotebookEdit,WebFetch,WebSearch,Task,Agent"
LIMIT_RE = re.compile(r"\blimit\b", re.I)
MAX_CONSECUTIVE_ERRORS = 3
RESET_RE = re.compile(r"resets?\b[^0-9]*?(\d{1,2})(?::(\d{2}))?\s*([ap]m)", re.I)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset", type=Path, default=ROOT / "eval/datasets/seed.jsonl")
    parser.add_argument("--samples", type=Path, default=ROOT / "eval/samples")
    parser.add_argument("--split", default="all", help="train / dev / test / all")
    parser.add_argument(
        "--subsets", default="", help="Comma-separated subsets to run, in this order."
    )
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--model", default="", help="Claude model alias or id (CLI default).")
    parser.add_argument("--max-turns", type=int, default=40)
    parser.add_argument("--timeout", type=int, default=900, help="Seconds per sample.")
    parser.add_argument(
        "--deadline", help="Local time 'YYYY-MM-DD HH:MM': start no sample after it."
    )
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--claude", default="claude", help="Claude CLI executable.")
    parser.add_argument("--lang", default="en")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parser.add_argument("--report", action="store_true", help="Only print the metrics.")
    parser.add_argument("--dry-run", action="store_true", help="Prepare, do not call Claude.")
    parser.add_argument("--yes", action="store_true", help="Confirm spending Claude usage.")
    return parser.parse_args(argv)


# --------------------------------------------------------------------------- workspace


class Workspace:
    def __init__(self, root: Path, lang: str) -> None:
        self.root = root
        self.cache = root / "cache"
        self.data = root / "data"
        self.profile = root / "profile"
        self.unpacked = root / "unpacked"
        self.cwd = root / "cwd"
        self.logs = root / "logs"
        self.results = root / "results.jsonl"
        self.mcp_config = root / "mcp.json"
        for path in (self.cache / "downloads", self.data, self.profile / "Default"):
            path.mkdir(parents=True, exist_ok=True)
        for path in (self.unpacked, self.cwd, self.logs):
            path.mkdir(parents=True, exist_ok=True)
        (self.profile / "Local State").write_text("{}", encoding="utf-8")
        server = {
            "command": str(Path(sys.executable).parent / "extrospect-mcp"),
            "args": ["--lang", lang],
            "env": {
                "EXTROSPECT_BROWSER_ROOTS": f"chromium={self.profile}",
                "EXTROSPECT_DATA_DIR": str(self.data),
                "EXTROSPECT_CACHE_DIR": str(self.cache),
            },
        }
        self.mcp_config.write_text(
            json.dumps({"mcpServers": {"extrospect": server}}, indent=1), encoding="utf-8"
        )

    def stage(self, row_id: str, sample: Path) -> str:
        """Make the sample reachable by id; returns the id the model is given."""
        installed: dict[str, Any] = {}
        if sample.is_dir():
            # Neutral folder name: fixture names such as "mal_..." must not leak labels.
            target = self.unpacked / hashlib.sha256(row_id.encode()).hexdigest()[:12]
            if not target.exists():
                shutil.copytree(sample, target)
            ext_id = id_from_path(target)
            installed[ext_id] = {"location": 4, "path": str(target.resolve())}
        else:
            ext_id = row_id
            link = self.cache / "downloads" / f"{row_id}_eval.crx"
            if not link.exists():
                link.symlink_to(sample.resolve())
        # Only the sample under test is "installed" during its session.
        (self.profile / "Default" / "Secure Preferences").write_text(
            json.dumps({"extensions": {"settings": installed}}), encoding="utf-8"
        )
        return ext_id

    def reports(self, ext_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        from extrospect.config import load_settings
        from extrospect.pipeline import Context

        settings = load_settings(
            overrides={"paths": {"data_dir": str(self.data), "cache_dir": str(self.cache)}}
        )
        ctx = Context.create(settings=settings, language="en")
        try:
            return ctx.cache.latest_report(ext_id, "host"), ctx.cache.latest_report(
                ext_id, "static"
            )
        finally:
            ctx.close()

    def done_ids(self) -> set[str]:
        if not self.results.exists():
            return set()
        return {r["id"] for r in read_results(self.results) if not r.get("error")}


def read_results(path: Path) -> list[dict[str, Any]]:
    """Latest record per sample id."""
    latest: dict[str, dict[str, Any]] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                latest[record["id"]] = record
    return list(latest.values())


# --------------------------------------------------------------------------- running


def reset_time(text: str, now: datetime) -> datetime | None:
    match = RESET_RE.search(text)
    if not match:
        return None
    hour = int(match.group(1)) % 12 + (12 if match.group(3).lower() == "pm" else 0)
    when = now.replace(hour=hour, minute=int(match.group(2) or 0), second=0, microsecond=0)
    while when <= now:
        when += timedelta(days=1)
    return when


def run_claude(
    args: argparse.Namespace, ws: Workspace, ext_id: str, timeout: int
) -> dict[str, Any]:
    cmd = [
        args.claude,
        "-p",
        "--output-format",
        "json",
        "--mcp-config",
        str(ws.mcp_config),
        "--strict-mcp-config",
        "--allowedTools",
        "mcp__extrospect",
        "--disallowedTools",
        DISALLOWED,
        "--max-turns",
        str(args.max_turns),
    ]
    if args.model:
        cmd += ["--model", args.model]
    # A clean environment: no variables of a parent Claude Code session leak in.
    env = {k: os.environ[k] for k in ("HOME", "PATH", "USER", "LANG") if k in os.environ}
    try:
        proc = subprocess.run(
            cmd,
            input=PROMPT.format(ext_id=ext_id),
            text=True,
            capture_output=True,
            cwd=ws.cwd,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"is_error": True, "result": f"timeout after {timeout}s"}
    (ws.logs / f"{ext_id}.json").write_text(proc.stdout or proc.stderr, encoding="utf-8")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"is_error": True, "result": (proc.stderr or proc.stdout or "")[:500]}


def evaluate(args: argparse.Namespace, ws: Workspace, rows: list[Any]) -> int:
    deadline = datetime.fromisoformat(args.deadline) if args.deadline else None
    done = ws.done_ids()
    errors_in_a_row = 0
    for row in rows:
        if row.id in done:
            continue
        sample = resolve_sample(row, args.samples, args.dataset.parent)
        if sample is None:
            continue
        ext_id = ws.stage(row.id, sample)
        if args.dry_run:
            print(f"would analyze {row.id} as {ext_id} ({sample})")
            continue
        while True:
            now = datetime.now()
            if deadline and now >= deadline:
                print(f"deadline {deadline:%Y-%m-%d %H:%M} reached - stopping", flush=True)
                return 0
            started = time.time()
            output = run_claude(args, ws, ext_id, args.timeout)
            text = str(output.get("result") or "")
            if output.get("is_error") and LIMIT_RE.search(text):
                resume = reset_time(text, datetime.now()) or datetime.now() + timedelta(minutes=30)
                resume += timedelta(minutes=2)
                if deadline and resume >= deadline:
                    print(f"usage limit until {resume:%H:%M}, past the deadline - stopping")
                    return 0
                print(f"usage limit - waiting until {resume:%H:%M}", flush=True)
                time.sleep(max(60.0, (resume - datetime.now()).total_seconds()))
                continue
            break
        host, static = ws.reports(ext_id)
        fresh = (
            bool(host)
            and host.get("created_at", "")
            >= datetime.fromtimestamp(started - 5).astimezone().isoformat()
        )
        verdict = (host or {}).get("verdict") or {}
        record = {
            "id": row.id,
            "label": row.label,
            "subset": row.subset,
            "family": row.family,
            "split": row.split,
            "model": args.model or "default",
            "static_score": (static or {}).get("score"),
            "has_verdict": fresh,
            "score": host.get("score") if fresh and host else (static or {}).get("score"),
            "level": host.get("level") if fresh and host else (static or {}).get("level"),
            "verdict": verdict.get("label") if fresh else None,
            "evidence_verified": sum(1 for e in verdict.get("evidence", []) if e.get("verified"))
            if fresh
            else 0,
            "cost_usd": output.get("total_cost_usd", 0.0),
            "num_turns": output.get("num_turns"),
            "duration_s": round(time.time() - started, 1),
            "error": text[:300] if output.get("is_error") else None,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
        }
        with ws.results.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        errors_in_a_row = errors_in_a_row + 1 if record["error"] else 0
        if errors_in_a_row >= MAX_CONSECUTIVE_ERRORS:
            print(f"{errors_in_a_row} failed samples in a row - stopping", flush=True)
            return 1
        print(
            f"{row.label:9} {row.subset:11} {row.id} static={record['static_score']} "
            f"host={record['score'] if fresh else '-'} verdict={record['verdict']} "
            f"${record['cost_usd'] or 0:.3f} {record['duration_s']}s",
            flush=True,
        )
    return 0


# --------------------------------------------------------------------------- report


def report(ws: Workspace, threshold: int) -> str:
    records = read_results(ws.results)

    def as_results(key: str, only_verdicts: bool = False) -> list[SampleResult]:
        return [
            SampleResult(
                id=r["id"],
                label=r["label"],
                subset=r["subset"],
                family=r["family"],
                score=r[key],
                verdict=r["verdict"],
                cost_usd=r.get("cost_usd") or 0.0,
                latency_s=r.get("duration_s") or 0.0,
            )
            for r in records
            if r[key] is not None and (r["has_verdict"] or not only_verdicts)
        ]

    lines = [
        f"Samples: {len(records)} (with a host verdict: "
        f"{sum(1 for r in records if r['has_verdict'])}); threshold: score >= {threshold}",
        "",
        "| Scores | n | Precision | Recall | FPR | Hard-benign FPR | AUC | $/ext | P95 latency |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, results in (
        ("static (quick_scan)", as_results("static_score")),
        ("host (final)", as_results("score")),
    ):
        m = compute_metrics(results, threshold)

        def pct(value: float | None) -> str:
            return "-" if value is None else f"{value * 100:.1f}%"

        auc = "-" if m.auc is None else f"{m.auc:.3f}"
        lines.append(
            f"| {name} | {m.n} | {pct(m.precision)} | {pct(m.recall)} | {pct(m.fpr)} | "
            f"{pct(m.hard_benign_fpr)} | {auc} | ${m.cost_per_ext:.3f} | {m.p95_latency_s:.0f}s |"
        )
    flagged = [r for r in records if (r["score"] or 0) >= threshold and r["label"] == "benign"]
    if flagged:
        lines += ["", "False positives (final score):"]
        lines += [f"- {r['id']} ({r['subset']}): {r['score']} {r['verdict']}" for r in flagged]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    work = args.work_dir or ROOT / "eval/runs" / f"host-{args.model or 'default'}"
    ws = Workspace(work, args.lang)
    if args.report:
        print(report(ws, args.threshold))
        return 0
    if not args.yes and not args.dry_run:
        print("This spends Claude usage for every sample; pass --yes to confirm.")
        return 2
    rows = load_dataset(args.dataset)
    if args.split != "all":
        rows = [r for r in rows if r.split == args.split]
    if args.subsets:
        order = [s.strip() for s in args.subsets.split(",") if s.strip()]
        rows = sorted((r for r in rows if r.subset in order), key=lambda r: order.index(r.subset))
    if args.limit:
        rows = rows[: args.limit]
    if shutil.which(args.claude) is None:
        print(f"Claude CLI not found: {args.claude}")
        return 2
    return evaluate(args, ws, rows)


if __name__ == "__main__":
    raise SystemExit(main())
