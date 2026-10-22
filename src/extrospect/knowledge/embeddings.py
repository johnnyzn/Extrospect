"""Embedding backends for the knowledge bases.

* ``hash`` (default): deterministic feature hashing of code token uni/bi-grams - free,
  offline, good at near-duplicate / same-technique code. Zero tokens.
* ``litellm:<model>``: any API embedding model through litellm (BYOK), e.g.
  ``litellm:text-embedding-3-small``.
* ``st:<model>``: a local sentence-transformers model, e.g.
  ``st:jinaai/jina-embeddings-v2-base-code`` (``pip install sentence-transformers``).

Which one retrieves best is decided by the RAG-B recall@5 evaluation (eval/retrieval.py).
"""

from __future__ import annotations

import hashlib
import itertools
import math
import re
from collections import Counter
from functools import cache
from typing import Protocol

_TOKEN_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|\d+(?:\.\d+)?|[^\sA-Za-z0-9_$]")
_OBF_RE = re.compile(r"^_0x[0-9a-f]+$")


class Embedder(Protocol):
    name: str
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


def code_tokens(text: str, limit: int = 40_000) -> list[str]:
    tokens: list[str] = []
    for token in _TOKEN_RE.findall(text[:limit]):
        if token[0].isdigit():
            tokens.append("<num>")
        elif _OBF_RE.match(token):
            tokens.append("<obf>")
        elif len(token) > 40:
            tokens.append("<long>")
        else:
            tokens.append(token.lower())
    return tokens


def _bucket(feature: str, dim: int) -> tuple[int, float]:
    digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
    value = int.from_bytes(digest, "little")
    return value % dim, 1.0 if (value >> 63) & 1 else -1.0


class HashEmbedder:
    def __init__(self, dim: int = 512) -> None:
        self.dim = dim
        self.name = f"hash-v1-{dim}"

    def embed_one(self, text: str) -> list[float]:
        tokens = code_tokens(text)
        features: Counter[str] = Counter(tokens)
        features.update(f"{a} {b}" for a, b in itertools.pairwise(tokens))
        vector = [0.0] * self.dim
        for feature, count in features.items():
            index, sign = _bucket(feature, self.dim)
            vector[index] += sign * (1.0 + math.log(count))
        norm = math.sqrt(sum(v * v for v in vector)) or 1.0
        return [v / norm for v in vector]

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self.embed_one(t) for t in texts]


class LiteLLMEmbedder:
    def __init__(self, model: str) -> None:
        import litellm

        self.litellm = litellm
        self.model = model
        self.name = f"litellm:{model}"
        self.dim = len(self.embed(["probe"])[0])

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = self.litellm.embedding(model=self.model, input=[t[:8000] for t in texts])
        return [list(map(float, item["embedding"])) for item in response.data]


class SentenceTransformerEmbedder:
    def __init__(self, model: str) -> None:
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer(model, trust_remote_code=True)
        self.name = f"st:{model}"
        self.dim = int(self.model.get_sentence_embedding_dimension())

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = self.model.encode(texts, normalize_embeddings=True)
        return [list(map(float, v)) for v in vectors]


@cache
def get_embedder(spec: str = "hash") -> Embedder:
    if spec == "hash" or spec.startswith("hash"):
        dim = int(spec.split(":", 1)[1]) if ":" in spec else 512
        return HashEmbedder(dim)
    if spec.startswith("litellm:"):
        return LiteLLMEmbedder(spec.split(":", 1)[1])
    if spec.startswith("st:"):
        return SentenceTransformerEmbedder(spec.split(":", 1)[1])
    raise ValueError(f"unknown embedding model spec: {spec}")


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


__all__ = [
    "Embedder",
    "HashEmbedder",
    "LiteLLMEmbedder",
    "SentenceTransformerEmbedder",
    "code_tokens",
    "cosine",
    "get_embedder",
]
