"""Store a local API key with Windows DPAPI for the current user account."""

from __future__ import annotations

import base64
import ctypes
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
    encrypted = _crypt(key.encode("utf-8"), decrypt=False)
    path.write_bytes(base64.b64encode(encrypted))


def load_key(path: Path) -> str:
    encrypted = base64.b64decode(path.read_bytes(), validate=True)
    return _crypt(encrypted, decrypt=True).decode("utf-8")
