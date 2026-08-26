"""Read and write the system clipboard from a console process.

The viewer does not need this -- it has Qt, and `QGuiApplication.clipboard()`
is already paid for. The host is a console program with no event loop, so it
talks to Win32 directly.

tkinter was the obvious stdlib answer and is the wrong one: Tk *owns* the
clipboard it sets, so everything the host pasted vanishes the moment the
process exits. Win32 hands the buffer to the OS, which is what the user
expects when they copy something on the remote machine and then hang up.

Anywhere that is not Windows this degrades to "no clipboard" rather than
failing, matching how capture falls back from dxcam to mss.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

available = sys.platform == "win32"

if available:
    _u32, _k32 = ctypes.windll.user32, ctypes.windll.kernel32
    # Every handle must be declared: a 64-bit HGLOBAL silently overflows the
    # c_int that ctypes assumes, and GlobalLock then fails on a garbage value.
    _k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _k32.GlobalAlloc.restype = wintypes.HGLOBAL
    _k32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    _k32.GlobalLock.restype = ctypes.c_void_p
    _k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    _u32.OpenClipboard.argtypes = [wintypes.HWND]
    _u32.GetClipboardData.argtypes = [wintypes.UINT]
    _u32.GetClipboardData.restype = wintypes.HANDLE
    _u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _u32.SetClipboardData.restype = wintypes.HANDLE


def paste() -> str | None:
    """The clipboard's text, or None if it holds something else or is locked.

    Another process can hold the clipboard open, so a failure here is normal
    and temporary -- the next poll gets it.
    """
    if not available or not _u32.OpenClipboard(None):
        return None
    try:
        handle = _u32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return None  # empty, or an image / file list we do not handle
        pointer = _k32.GlobalLock(handle)
        if not pointer:
            return None
        try:
            return ctypes.c_wchar_p(pointer).value
        finally:
            _k32.GlobalUnlock(handle)
    finally:
        _u32.CloseClipboard()


def copy(text: str) -> bool:
    """Put text on the clipboard. Returns False if the clipboard was busy."""
    if not available:
        return False
    buffer = ctypes.create_unicode_buffer(text)
    size = ctypes.sizeof(buffer)
    handle = _k32.GlobalAlloc(GMEM_MOVEABLE, size)
    if not handle:
        return False
    pointer = _k32.GlobalLock(handle)
    if not pointer:
        return False
    ctypes.memmove(pointer, buffer, size)
    _k32.GlobalUnlock(handle)
    if not _u32.OpenClipboard(None):
        return False
    try:
        _u32.EmptyClipboard()
        _u32.SetClipboardData(CF_UNICODETEXT, handle)  # the OS owns handle now
        return True
    finally:
        _u32.CloseClipboard()


if __name__ == "__main__":
    print(f"clipboard available: {available}")
    original = paste()
    print(f"currently holds: {original!r}")
    assert copy("clipboard self-test"), "could not write the clipboard"
    assert paste() == "clipboard self-test", "wrote it but read something else"
    print("round trip ok")
    if original is not None:
        copy(original)  # put the user's own clipboard back
        print("restored what was there before")
