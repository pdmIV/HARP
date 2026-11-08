"""User-local API keys: Windows DPAPI or owner-only POSIX files."""

from __future__ import annotations

import base64
import ctypes
import os
import stat
from ctypes import wintypes
from pathlib import Path


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(value: bytes):
    buffer = ctypes.create_string_buffer(value)
    return DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _crypt(value: bytes, *, decrypt: bool) -> bytes:
    if not hasattr(ctypes, "windll"):
        raise RuntimeError("Windows DPAPI is required")
    input_blob, buffer = _blob(value)
    output_blob = DataBlob()
    crypt32 = ctypes.windll.crypt32
    function = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    function.restype = wintypes.BOOL
    function.argtypes = (
        [ctypes.POINTER(DataBlob), ctypes.c_void_p, ctypes.POINTER(DataBlob),
         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob)]
        if decrypt else
        [ctypes.POINTER(DataBlob), wintypes.LPCWSTR, ctypes.POINTER(DataBlob),
         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob)]
    )
    args = ([ctypes.byref(input_blob), None, None, None, None, 1, ctypes.byref(output_blob)]
            if decrypt else
            [ctypes.byref(input_blob), "HARP Unsloth API key", None, None, None, 1,
             ctypes.byref(output_blob)])
    if not function(*args):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(output_blob.pbData, ctypes.c_void_p))


def save_key(path: Path, key: str) -> None:
    if not key:
        raise ValueError("No key was entered")
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.parent.chmod(0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(b"HARP-POSIX-1\n" + key.encode("utf-8"))
        return
    encrypted = _crypt(key.encode("utf-8"), decrypt=False)
    path.write_bytes(base64.b64encode(encrypted))


def load_key(path: Path) -> str:
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise RuntimeError("API key file must belong to the current user with mode 600")
            data = stream.read(65536)
        if not data.startswith(b"HARP-POSIX-1\n"):
            raise RuntimeError("Reimport this API key on Kali; Windows DPAPI keys cannot be migrated")
        return data.split(b"\n", 1)[1].decode("utf-8")
    encrypted = base64.b64decode(path.read_bytes(), validate=True)
    return _crypt(encrypted, decrypt=True).decode("utf-8")
