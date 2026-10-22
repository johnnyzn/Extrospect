"""Shared HTTP client: one place for the user agent, timeouts, offline mode and rate limits.

Every network request Extrospect makes goes through :class:`HttpClient`, which makes the
privacy promise ("nothing about your installed extensions is uploaded") auditable:
the only outbound requests are CRX downloads, store listing pages, EPSS scores (CVE
ids only), RDAP domain lookups, the retire.js vulnerability repository and advisories.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx

from extrospect.config import NetworkConfig


class OfflineError(RuntimeError):
    """Raised when a network request is attempted while offline mode is on."""


class HttpClient:
    def __init__(self, cfg: NetworkConfig, transport: httpx.BaseTransport | None = None) -> None:
        self.cfg = cfg
        self._client = httpx.Client(
            headers={"User-Agent": cfg.user_agent, "Accept-Language": "en"},
            timeout=cfg.timeout_s,
            follow_redirects=True,
            transport=transport,
        )
        self._lock = threading.Lock()
        self._last_request: dict[str, float] = {}

    @property
    def offline(self) -> bool:
        return self.cfg.offline

    def _throttle(self, host_key: str, per_second: float | None) -> None:
        if not per_second or per_second <= 0:
            return
        interval = 1.0 / per_second
        with self._lock:
            last = self._last_request.get(host_key, 0.0)
            wait = last + interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_request[host_key] = time.monotonic()

    def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        rate_key: str | None = None,
        per_second: float | None = None,
        retries: int = 2,
        timeout: float | None = None,
    ) -> httpx.Response:
        if self.cfg.offline:
            raise OfflineError(f"offline mode: refusing to fetch {url}")
        self._throttle(rate_key or httpx.URL(url).host, per_second)
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            try:
                response = self._client.get(
                    url, params=params, headers=headers, timeout=timeout or self.cfg.timeout_s
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
            else:
                if response.status_code in {429, 500, 502, 503, 504} and attempt < retries:
                    time.sleep(min(8.0, 1.5 * (2**attempt)))
                    continue
                return response
            if attempt < retries:
                time.sleep(min(8.0, 1.5 * (2**attempt)))
        assert last_exc is not None
        raise last_exc

    def get_json(self, url: str, **kwargs: Any) -> Any:
        response = self.get(url, **kwargs)
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["HttpClient", "OfflineError"]
