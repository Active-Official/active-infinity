"""Active Infinity for Python (ctypes binding over the C ABI).

One canonicalizer: validation, content hash, canonical re-encode and redacted
JSON all call the Rust reference, so bytes cannot drift from the format.

    pip install -e polyglot/python      # or point ACTIVE_INFINITY_LIB at the library
    python -m active_infinity.conformance tests/vectors/valid/full.ainf

The shared library is located from ``ACTIVE_INFINITY_LIB`` when set, otherwise
from the repository build directory, otherwise from the system loader.
"""

from __future__ import annotations

import ctypes
import os
import pathlib
import sys
from dataclasses import dataclass

ABI_VERSION = 1

_LIBRARY_NAMES = {
    "win32": ("active_infinity_ffi.dll",),
    "darwin": ("libactive_infinity_ffi.dylib",),
    "linux": ("libactive_infinity_ffi.so",),
}

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_BUILD_DIR = _REPO_ROOT / "ffi" / "active-infinity-ffi" / "target" / "release"


class ActiveInfinityError(Exception):
    """A stable ``infinity/...`` failure from the reference codec."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(f"{code} (status {status})")
        self.code = code
        self.status = status


def _candidate_paths() -> list[pathlib.Path]:
    override = os.environ.get("ACTIVE_INFINITY_LIB")
    candidates: list[pathlib.Path] = []
    if override:
        candidates.append(pathlib.Path(override))
    for name in _LIBRARY_NAMES.get(sys.platform, ("libactive_infinity_ffi.so",)):
        candidates.append(_BUILD_DIR / name)
        candidates.append(pathlib.Path(name))
    return candidates


def _load() -> ctypes.CDLL:
    errors: list[str] = []
    for candidate in _candidate_paths():
        try:
            return ctypes.CDLL(str(candidate))
        except OSError as error:  # pragma: no cover - depends on the machine
            errors.append(f"{candidate}: {error}")
    raise ActiveInfinityError("infinity/library-not-found: " + "; ".join(errors), -1)


_lib = _load()


class Limits(ctypes.Structure):
    """Caller-supplied budget (INF-FFI-02): one ceiling per field, in the
    same order as the C `active_infinity_limits` struct.

    Build one from the library defaults with `Limits.default()`, then
    override the ceiling to tighten. A ceiling of zero is refused
    (`infinity/invalid-argument`).
    """

    _fields_ = [
        ("max_nodes", ctypes.c_uint32),
        ("max_edges", ctypes.c_uint32),
        ("max_children", ctypes.c_uint32),
        ("max_fields", ctypes.c_uint32),
        ("max_parts", ctypes.c_uint32),
        ("max_strings", ctypes.c_uint32),
        ("max_string_bytes", ctypes.c_uint32),
        ("max_blobs", ctypes.c_uint32),
        ("max_blob_bytes", ctypes.c_uint32),
        ("max_annotations", ctypes.c_uint32),
        ("max_units", ctypes.c_uint32),
        ("max_types", ctypes.c_uint32),
        ("max_aux", ctypes.c_uint32),
        ("max_numbers", ctypes.c_uint32),
        ("max_secrets", ctypes.c_uint32),
        ("max_secret_bytes", ctypes.c_uint32),
        ("max_extensions", ctypes.c_uint32),
        ("max_prov_bytes", ctypes.c_uint32),
        ("max_prov_entries", ctypes.c_uint32),
        ("max_hashes", ctypes.c_uint32),
        ("max_bindings", ctypes.c_uint32),
        ("max_total_bytes", ctypes.c_uint64),
        ("max_decoded_bytes", ctypes.c_uint64),
        ("max_depth", ctypes.c_uint32),
    ]

    @classmethod
    def default(cls) -> Limits:
        """Fill a Limits with the library defaults (via the FFI)."""
        limits = cls()
        _check(_lib.active_infinity_limits_default(ctypes.byref(limits)))
        return limits


_lib.active_infinity_abi_version.restype = ctypes.c_uint32
_lib.active_infinity_last_error.restype = ctypes.c_char_p
_lib.active_infinity_validate.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_lib.active_infinity_validate.restype = ctypes.c_int32
_lib.active_infinity_validate_canonical.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_lib.active_infinity_validate_canonical.restype = ctypes.c_int32
_lib.active_infinity_limits_default.argtypes = [ctypes.POINTER(Limits)]
_lib.active_infinity_limits_default.restype = ctypes.c_int32
_lib.active_infinity_validate_with_limits.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(Limits),
]
_lib.active_infinity_validate_with_limits.restype = ctypes.c_int32
_lib.active_infinity_decode_with_limits.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(Limits),
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.active_infinity_decode_with_limits.restype = ctypes.c_int32
_lib.active_infinity_content_hash.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
]
_lib.active_infinity_content_hash.restype = ctypes.c_int32
for _name in ("active_infinity_reencode", "active_infinity_redacted_json"):
    _function = getattr(_lib, _name)
    _function.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _function.restype = ctypes.c_int32
_lib.active_infinity_from_active.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.active_infinity_from_active.restype = ctypes.c_int32

if _lib.active_infinity_abi_version() != ABI_VERSION:
    raise ActiveInfinityError("infinity/abi-mismatch", -1)


def _last_error() -> str:
    text = _lib.active_infinity_last_error()
    return text.decode("utf-8", "replace") if text else "infinity/unknown"


def _check(status: int) -> None:
    if status != 0:
        raise ActiveInfinityError(_last_error(), status)


def _buffer(data: bytes) -> tuple[ctypes.Array | None, int]:
    if not data:
        return None, 0
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data), len(data)


def _pointer(buffer: ctypes.Array | None) -> ctypes.c_void_p:
    return ctypes.cast(buffer, ctypes.c_void_p) if buffer is not None else None


def _call_output(function, payload: bytes, *prefix) -> bytes:
    buffer, length = _buffer(payload)
    out_len = ctypes.c_size_t(0)
    status = function(_pointer(buffer), length, *prefix, None, ctypes.byref(out_len))
    if status != -2 or out_len.value == 0:
        _check(status)
        return b""
    out = (ctypes.c_ubyte * out_len.value)()
    capacity = ctypes.c_size_t(out_len.value)
    status = function(_pointer(buffer), length, *prefix, out, ctypes.byref(capacity))
    _check(status)
    return bytes(out[: capacity.value])


@dataclass(frozen=True)
class Image:
    """An AINF image with the reference operations attached."""

    data: bytes

    def validate(self) -> Image:
        buffer, length = _buffer(self.data)
        _check(_lib.active_infinity_validate(_pointer(buffer), length))
        return self

    def validate_canonical(self) -> Image:
        # INF-POLY-03: `validate` already proves the canonical form
        # (INF-02); this states the requirement explicitly, matching
        # `active_infinity_validate_canonical` in the C ABI.
        buffer, length = _buffer(self.data)
        _check(_lib.active_infinity_validate_canonical(_pointer(buffer), length))
        return self

    def validate_with_limits(self, limits: Limits | None = None) -> Image:
        # INF-FFI-02: the limits-parameterized form of validate_canonical.
        # None means the library defaults.
        buffer, length = _buffer(self.data)
        pointer = ctypes.byref(limits) if limits is not None else None
        _check(
            _lib.active_infinity_validate_with_limits(_pointer(buffer), length, pointer)
        )
        return self

    def decode_with_limits(self, limits: Limits | None = None) -> bytes:
        # INF-FFI-02: the limits-parameterized form of reencode.
        pointer = ctypes.byref(limits) if limits is not None else None
        return _call_output(
            _lib.active_infinity_decode_with_limits, self.data, pointer
        )

    def content_hash(self) -> bytes:
        buffer, length = _buffer(self.data)
        out = (ctypes.c_ubyte * 32)()
        _check(_lib.active_infinity_content_hash(_pointer(buffer), length, out))
        return bytes(out)

    def content_hash_hex(self) -> str:
        return self.content_hash().hex()

    def reencode(self) -> bytes:
        return _call_output(_lib.active_infinity_reencode, self.data)

    def redacted_json(self) -> str:
        return _call_output(_lib.active_infinity_redacted_json, self.data).decode()

    @staticmethod
    def from_active(source: str | bytes, name: str = "module.active") -> bytes:
        payload = source.encode() if isinstance(source, str) else source
        return _call_output(
            _lib.active_infinity_from_active,
            payload,
            name.encode() + b"\x00",
        )


def version() -> str:
    """Library version reported by the C ABI."""
    _lib.active_infinity_version.restype = ctypes.c_char_p
    text = _lib.active_infinity_version()
    return text.decode() if text else "unknown"
