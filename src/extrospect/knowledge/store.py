"""Embedded vector store: LanceDB when installed (``extrospect[rag]``), otherwise a small
SQLite + brute-force cosine fallback that is plenty for a few thousand entries.

Collections are namespaced by embedder (``<collection>__<embedder>``) so switching the
embedding model never mixes incompatible vectors.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from extrospect.config import Settings


@dataclass
class Hit:
    id: str
    score: float  # cosine similarity
    text: str
    metadata: dict[str, Any]


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_")[:80]


class VectorStore:
    backend = "abstract"

    def add(
        self,
        collection: str,
        embedder: str,
        items: list[tuple[str, list[float], str, dict[str, Any]]],
    ) -> int:
        raise NotImplementedError

    def search(self, collection: str, embedder: str, vector: list[float], k: int) -> list[Hit]:
        raise NotImplementedError

    def count(self, collection: str, embedder: str) -> int:
        raise NotImplementedError

    def stats(self) -> dict[str, int]:
        raise NotImplementedError


class SimpleStore(VectorStore):
    backend = "simple"

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.RLock()
        self._memo: dict[tuple[str, str], list[tuple[str, list[float], str, dict[str, Any]]]] = {}
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS vectors (collection TEXT, embedder TEXT, id TEXT, vector BLOB, "
                "text TEXT, metadata TEXT, PRIMARY KEY (collection, embedder, id))"
            )
            self._conn.commit()

    def add(
        self,
        collection: str,
        embedder: str,
        items: list[tuple[str, list[float], str, dict[str, Any]]],
    ) -> int:
        with self._lock:
            self._conn.executemany(
                "INSERT OR REPLACE INTO vectors VALUES (?,?,?,?,?,?)",
                [
                    (
                        collection,
                        embedder,
                        item_id,
                        struct.pack(f"<{len(vec)}f", *vec),
                        text,
                        json.dumps(meta, ensure_ascii=False),
                    )
                    for item_id, vec, text, meta in items
                ],
            )
            self._conn.commit()
            self._memo.pop((collection, embedder), None)
        return len(items)

    def _load(
        self, collection: str, embedder: str
    ) -> list[tuple[str, list[float], str, dict[str, Any]]]:
        key = (collection, embedder)
        if key not in self._memo:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT id, vector, text, metadata FROM vectors WHERE collection=? AND embedder=?",
                    key,
                ).fetchall()
            self._memo[key] = [
                (
                    row[0],
                    list(struct.unpack(f"<{len(row[1]) // 4}f", row[1])),
                    row[2],
                    json.loads(row[3]),
                )
                for row in rows
            ]
        return self._memo[key]

    def search(self, collection: str, embedder: str, vector: list[float], k: int) -> list[Hit]:
        rows = self._load(collection, embedder)
        if not rows:
            return []
        try:
            import numpy as np

            matrix = np.array([r[1] for r in rows], dtype="float32")
            query = np.array(vector, dtype="float32")
            norms = np.linalg.norm(matrix, axis=1) * (np.linalg.norm(query) or 1.0)
            scores = (matrix @ query) / np.where(norms == 0, 1.0, norms)
            order = np.argsort(-scores)[:k]
            return [Hit(rows[i][0], float(scores[i]), rows[i][2], rows[i][3]) for i in order]
        except ImportError:
            qn = math.sqrt(sum(v * v for v in vector)) or 1.0
            scored = []
            for item_id, vec, text, meta in rows:
                vn = math.sqrt(sum(v * v for v in vec)) or 1.0
                scored.append(
                    (
                        sum(a * b for a, b in zip(vec, vector, strict=False)) / (vn * qn),
                        item_id,
                        text,
                        meta,
                    )
                )
            scored.sort(key=lambda x: -x[0])
            return [Hit(i, s, t, m) for s, i, t, m in scored[:k]]

    def count(self, collection: str, embedder: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM vectors WHERE collection=? AND embedder=?",
                (collection, embedder),
            ).fetchone()
        return int(row[0])

    def stats(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT collection, embedder, COUNT(*) FROM vectors GROUP BY 1, 2"
            ).fetchall()
        return {f"{c} [{e}]": int(n) for c, e, n in rows}


class LanceStore(VectorStore):
    backend = "lancedb"

    def __init__(self, path: Path) -> None:
        import lancedb

        path.mkdir(parents=True, exist_ok=True)
        self.db = lancedb.connect(str(path))
        self._lock = threading.RLock()

    def _name(self, collection: str, embedder: str) -> str:
        return f"{_slug(collection)}__{_slug(embedder)}"

    def _table(self, name: str) -> Any:
        try:
            return self.db.open_table(name)
        except Exception:
            return None

    def add(
        self,
        collection: str,
        embedder: str,
        items: list[tuple[str, list[float], str, dict[str, Any]]],
    ) -> int:
        if not items:
            return 0
        rows = [
            {
                "id": item_id,
                "vector": [float(v) for v in vec],
                "text": text,
                "metadata": json.dumps(meta, ensure_ascii=False),
            }
            for item_id, vec, text, meta in items
        ]
        name = self._name(collection, embedder)
        with self._lock:
            table = self._table(name)
            if table is None:
                try:
                    self.db.create_table(name, data=rows)
                    return len(rows)
                except Exception:
                    # Created concurrently by another instance/process: upsert instead.
                    table = self._table(name)
                    if table is None:
                        raise
            table.merge_insert(
                "id"
            ).when_matched_update_all().when_not_matched_insert_all().execute(rows)
        return len(rows)

    def search(self, collection: str, embedder: str, vector: list[float], k: int) -> list[Hit]:
        table = self._table(self._name(collection, embedder))
        if table is None:
            return []
        query = table.search([float(v) for v in vector])
        try:
            query = query.distance_type("cosine")
        except AttributeError:  # older lancedb
            query = query.metric("cosine")
        results = query.limit(k).to_list()
        return [
            Hit(
                str(r["id"]),
                1.0 - float(r.get("_distance", 1.0)),
                str(r.get("text", "")),
                json.loads(r.get("metadata") or "{}"),
            )
            for r in results
        ]

    def count(self, collection: str, embedder: str) -> int:
        table = self._table(self._name(collection, embedder))
        return int(table.count_rows()) if table is not None else 0

    def stats(self) -> dict[str, int]:
        try:
            names = list(self.db.table_names())
        except Exception:
            names = []
        stats = {}
        for name in names:
            table = self._table(name)
            if table is not None:
                stats[name] = int(table.count_rows())
        return stats


_STORES: dict[str, VectorStore] = {}
_STORES_LOCK = threading.Lock()


def open_store(settings: Settings) -> VectorStore:
    with _STORES_LOCK:  # MCP tools run in worker threads: exactly one store per directory
        return _open_store(settings)


def _open_store(settings: Settings) -> VectorStore:
    directory = settings.paths.knowledge_dir
    backend = settings.knowledge.vector_backend
    key = f"{directory}|{backend}"
    if key in _STORES:
        return _STORES[key]
    store: VectorStore
    if backend in {"auto", "lancedb"}:
        try:
            store = LanceStore(directory / "lancedb")
        except ImportError:
            if backend == "lancedb":
                raise
            store = SimpleStore(directory / "vectors.sqlite3")
    else:
        store = SimpleStore(directory / "vectors.sqlite3")
    _STORES[key] = store
    return store


__all__ = ["Hit", "LanceStore", "SimpleStore", "VectorStore", "open_store"]
