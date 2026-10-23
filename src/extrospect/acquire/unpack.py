"""CRX2/CRX3 parsing and safe extraction (zip-slip and zip-bomb protection).

CRX3 layout: ``"Cr24"`` | uint32 LE version (3) | uint32 LE header length | protobuf
``CrxFileHeader`` | ZIP. The extension id is the ``crx_id`` inside the signed header data
(first 16 bytes of the SHA-256 of the publisher key), mapped to ``a``-``p``.
"""

from __future__ import annotations

import io
import shutil
import stat
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

from extrospect.static.manifest import id_from_bytes, id_from_public_key
from extrospect.util import PathEscapeError, safe_join

CRX_MAGIC = b"Cr24"
ZIP_MAGIC = b"PK\x03\x04"
# Real extensions reach several hundred MB unpacked (ad-block filter lists, WASM models).
DEFAULT_MAX_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_FILES = 20_000
# Zip-bomb guard: a large member that expands far beyond its compressed size.
BOMB_MIN_BYTES = 64 * 1024 * 1024
BOMB_RATIO = 200


class UnpackError(ValueError):
    """The package is malformed, unsafe or too large."""


@dataclass
class CrxInfo:
    format: str  # "crx3" / "crx2" / "zip"
    zip_offset: int
    extension_id: str | None = None
    public_key: bytes | None = None


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data):
            raise UnpackError("truncated varint in CRX header")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise UnpackError("varint too long in CRX header")


def parse_protobuf(data: bytes) -> dict[int, list[bytes | int]]:
    """Minimal protobuf wire-format reader (enough for CrxFileHeader / SignedData)."""
    fields: dict[int, list[bytes | int]] = {}
    pos = 0
    while pos < len(data):
        key, pos = _read_varint(data, pos)
        number, wire_type = key >> 3, key & 7
        if wire_type == 0:
            value, pos = _read_varint(data, pos)
            fields.setdefault(number, []).append(value)
        elif wire_type == 2:
            length, pos = _read_varint(data, pos)
            if pos + length > len(data):
                raise UnpackError("truncated field in CRX header")
            fields.setdefault(number, []).append(data[pos : pos + length])
            pos += length
        elif wire_type == 1:
            pos += 8
        elif wire_type == 5:
            pos += 4
        else:
            raise UnpackError(f"unsupported protobuf wire type {wire_type}")
    return fields


def parse_crx_header(data: bytes) -> CrxInfo:
    if data.startswith((ZIP_MAGIC, b"PK")):
        return CrxInfo(format="zip", zip_offset=0)
    if not data.startswith(CRX_MAGIC) or len(data) < 12:
        raise UnpackError("not a CRX or ZIP file")
    version = struct.unpack_from("<I", data, 4)[0]
    if version == 3:
        header_len = struct.unpack_from("<I", data, 8)[0]
        header_end = 12 + header_len
        if header_end > len(data):
            raise UnpackError("CRX3 header exceeds file size")
        header = parse_protobuf(data[12:header_end])
        info = CrxInfo(format="crx3", zip_offset=header_end)
        signed = header.get(10000)
        if signed and isinstance(signed[0], bytes):
            crx_id = parse_protobuf(signed[0]).get(1)
            if crx_id and isinstance(crx_id[0], bytes) and len(crx_id[0]) >= 16:
                info.extension_id = id_from_bytes(crx_id[0])
        for proof_field in (2, 3):  # sha256_with_rsa, sha256_with_ecdsa
            for proof in header.get(proof_field, []):
                if isinstance(proof, bytes):
                    key = parse_protobuf(proof).get(1)
                    if key and isinstance(key[0], bytes):
                        info.public_key = info.public_key or key[0]
        if info.extension_id is None and info.public_key:
            info.extension_id = id_from_public_key(info.public_key)
        return info
    if version == 2:
        key_len, sig_len = struct.unpack_from("<II", data, 8)
        start = 16
        public_key = data[start : start + key_len]
        return CrxInfo(
            format="crx2",
            zip_offset=start + key_len + sig_len,
            public_key=public_key,
            extension_id=id_from_public_key(public_key) if public_key else None,
        )
    raise UnpackError(f"unsupported CRX version {version}")


def extract_zip(
    zip_bytes: bytes,
    dest: Path,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
) -> int:
    """Extract safely; returns the number of files written."""
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise UnpackError(f"invalid zip archive: {exc}") from exc
    with archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            if info.is_dir() or name.endswith("/"):
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                continue  # never materialise symlinks from an archive
            try:
                target = safe_join(dest, name)
            except PathEscapeError as exc:
                raise UnpackError(f"unsafe path in archive: {name}") from exc
            count += 1
            if count > max_files:
                raise UnpackError(f"archive has more than {max_files} files")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info) as src, target.open("wb") as dst:
                while chunk := src.read(1 << 16):
                    total += len(chunk)
                    written += len(chunk)
                    if total > max_bytes:
                        raise UnpackError(f"archive expands beyond {max_bytes} bytes")
                    if written > BOMB_MIN_BYTES and written > BOMB_RATIO * max(
                        info.compress_size, 1
                    ):
                        raise UnpackError(f"suspicious compression ratio in {name}")
                    dst.write(chunk)
    return count


def unpack_package(
    data: bytes,
    dest: Path,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
) -> CrxInfo:
    """Unpack a CRX/ZIP into ``dest`` (replacing it). Returns header information."""
    info = parse_crx_header(data)
    if dest.exists():
        shutil.rmtree(dest)
    try:
        extract_zip(data[info.zip_offset :], dest, max_bytes=max_bytes, max_files=max_files)
    except UnpackError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return info


def unpack_file(path: Path, dest: Path, **kwargs: int) -> CrxInfo:
    return unpack_package(path.read_bytes(), dest, **kwargs)


__all__ = [
    "CRX_MAGIC",
    "CrxInfo",
    "UnpackError",
    "extract_zip",
    "parse_crx_header",
    "parse_protobuf",
    "unpack_file",
    "unpack_package",
]
