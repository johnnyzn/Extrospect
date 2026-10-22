"""Download the current CRX of an extension from Chrome's public update endpoint.

Only the *latest* published version is available; removed extensions cannot be
downloaded this way (the endpoint answers 204/404) - the evaluation set needs other
sources for those. Requests are rate-limited (1/s by default) and identify the client.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from extrospect.acquire.unpack import CRX_MAGIC, UnpackError, parse_crx_header
from extrospect.config import Settings
from extrospect.http import HttpClient
from extrospect.models import EXTENSION_ID_RE
from extrospect.util import sha256_bytes

UPDATE_ENDPOINT = "https://clients2.google.com/service/update2/crx"


class DownloadError(RuntimeError):
    pass


class ExtensionUnavailable(DownloadError):
    """The store does not serve this id (removed, private, or wrong id)."""


@dataclass
class DownloadResult:
    ext_id: str
    path: Path
    sha256: str
    size: int
    crx_format: str


def download_url(ext_id: str, prodversion: str) -> str:
    x = quote(f"id={ext_id}&uc", safe="")
    return (
        f"{UPDATE_ENDPOINT}?response=redirect&prodversion={prodversion}"
        f"&acceptformat=crx2,crx3&x={x}"
    )


def download_crx(
    ext_id: str, settings: Settings, http: HttpClient, dest_dir: Path | None = None
) -> DownloadResult:
    ext_id = ext_id.strip().lower()
    if not EXTENSION_ID_RE.match(ext_id):
        raise DownloadError(f"invalid extension id: {ext_id!r} (expected 32 letters a-p)")
    url = download_url(ext_id, settings.network.crx_prodversion)
    response = http.get(
        url,
        rate_key="chrome-webstore",
        per_second=settings.network.webstore_requests_per_s,
        timeout=max(60.0, settings.network.timeout_s),
    )
    if response.status_code in {204, 404}:
        raise ExtensionUnavailable(f"{ext_id} is not available from the Chrome Web Store")
    if response.status_code >= 400:
        raise DownloadError(f"download failed with HTTP {response.status_code}")
    data = response.content
    if not data.startswith(CRX_MAGIC):
        raise ExtensionUnavailable(f"{ext_id}: the update server did not return a CRX file")
    try:
        info = parse_crx_header(data)
    except UnpackError as exc:
        raise DownloadError(f"{ext_id}: corrupt CRX ({exc})") from exc
    target_dir = dest_dir or settings.paths.downloads_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    digest = sha256_bytes(data)
    path = target_dir / f"{ext_id}_{digest[:12]}.crx"
    path.write_bytes(data)
    return DownloadResult(
        ext_id=ext_id, path=path, sha256=digest, size=len(data), crx_format=info.format
    )


__all__ = [
    "DownloadError",
    "DownloadResult",
    "ExtensionUnavailable",
    "download_crx",
    "download_url",
]
