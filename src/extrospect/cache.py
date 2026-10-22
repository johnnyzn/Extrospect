"""SQLite-backed cache for file analyses, triage results, reports and HTTP lookups.

One table per concern keeps cache invalidation explicit:

* ``files``    - per-file static analysis keyed by ``sha256(file)`` + analyser version
* ``triage``   - triage results keyed by ``(slice_id, prompt_version, model, language)``
* ``reports``  - full reports keyed by ``(ext_id, version, pipeline_version, mode)``
* ``kv``       - namespaced key/value with optional expiry (EPSS, listings, RDAP, ...)
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    sha256 TEXT NOT NULL,
    analyzer TEXT NOT NULL,
    data TEXT NOT NULL,
    created REAL NOT NULL,
    PRIMARY KEY (sha256, analyzer)
);
CREATE TABLE IF NOT EXISTS triage (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    ext_id TEXT NOT NULL,
    version TEXT NOT NULL,
    pipeline_version TEXT NOT NULL,
    mode TEXT NOT NULL,
    language TEXT NOT NULL,
    data TEXT NOT NULL,
    created REAL NOT NULL,
    PRIMARY KEY (ext_id, version, pipeline_version, mode)
);
CREATE INDEX IF NOT EXISTS reports_by_ext ON reports (ext_id, created);
CREATE TABLE IF NOT EXISTS kv (
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    expires REAL,
    PRIMARY KEY (namespace, key)
);
"""


class Cache:
    """Thread-safe (single connection + lock) SQLite cache. ``path=None`` = in-memory."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(path) if path is not None else ":memory:",
            check_same_thread=False,
            timeout=30,
        )
        with self._lock:
            if path is not None:
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ files

    def get_file(self, sha256: str, analyzer: str) -> Any | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM files WHERE sha256=? AND analyzer=?", (sha256, analyzer)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put_file(self, sha256: str, analyzer: str, data: Any) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO files VALUES (?,?,?,?)",
                (sha256, analyzer, json.dumps(data, ensure_ascii=False), time.time()),
            )

    # ------------------------------------------------------------------ triage

    @staticmethod
    def triage_key(slice_id: str, prompt_version: str, model: str, language: str) -> str:
        return f"{slice_id}|{prompt_version}|{model}|{language}"

    def get_triage(self, key: str) -> Any | None:
        with self._lock:
            row = self._conn.execute("SELECT data FROM triage WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put_triage(self, key: str, data: Any) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO triage VALUES (?,?,?)",
                (key, json.dumps(data, ensure_ascii=False), time.time()),
            )

    # ------------------------------------------------------------------ reports

    def get_report(
        self, ext_id: str, version: str, pipeline_version: str, mode: str
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM reports WHERE ext_id=? AND version=? AND pipeline_version=? AND mode=?",
                (ext_id, version, pipeline_version, mode),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put_report(
        self,
        ext_id: str,
        version: str,
        pipeline_version: str,
        mode: str,
        language: str,
        data: dict[str, Any],
    ) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?,?)",
                (
                    ext_id,
                    version,
                    pipeline_version,
                    mode,
                    language,
                    json.dumps(data, ensure_ascii=False, default=str),
                    time.time(),
                ),
            )

    def latest_report(self, ext_id: str, mode: str | None = None) -> dict[str, Any] | None:
        query = "SELECT data FROM reports WHERE ext_id=?"
        params: tuple[Any, ...] = (ext_id,)
        if mode:
            query += " AND mode=?"
            params += (mode,)
        query += " ORDER BY created DESC LIMIT 1"
        with self._lock:
            row = self._conn.execute(query, params).fetchone()
        return json.loads(row[0]) if row else None

    def list_reports(self, limit: int = 100) -> list[tuple[str, str, str, float]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ext_id, version, mode, created FROM reports ORDER BY created DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [(r[0], r[1], r[2], r[3]) for r in rows]

    # ------------------------------------------------------------------ kv

    def get_kv(self, namespace: str, key: str) -> Any | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value, expires FROM kv WHERE namespace=? AND key=?", (namespace, key)
            ).fetchone()
        if not row:
            return None
        value, expires = row
        if expires is not None and expires < time.time():
            return None
        return json.loads(value)

    def put_kv(self, namespace: str, key: str, value: Any, ttl_s: float | None = None) -> None:
        expires = time.time() + ttl_s if ttl_s else None
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO kv VALUES (?,?,?,?)",
                (namespace, key, json.dumps(value, ensure_ascii=False, default=str), expires),
            )

    # ------------------------------------------------------------------ maintenance

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                table: int(self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("files", "triage", "reports", "kv")
            }

    def clear(self, tables: tuple[str, ...] = ("files", "triage", "reports", "kv")) -> None:
        allowed = {"files", "triage", "reports", "kv"}
        with self._tx() as conn:
            for table in tables:
                if table in allowed:
                    conn.execute(f"DELETE FROM {table}")


__all__ = ["Cache"]
