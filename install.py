"""One-shot setup: install the dependencies, then prove this machine can run it.

    python install.py

Installing is the easy half. The half that actually saves you time is the
report at the end: which capture backend and which H.264 encoder this machine
ended up with, checked by really using them rather than by importing and hoping.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

MIN_PYTHON = (3, 10)
ROOT = Path(__file__).resolve().parent

# import name -> what it is for, so a failure says something useful
CHECKS = [
    ("av", "H.264 encode and decode"),
    ("cv2", "image scaling"),
    ("numpy", "frame buffers"),
    ("mss", "screen capture fallback"),
    ("pynput", "input injection (host only)"),
    ("PySide6", "viewer window"),
    ("cryptography", "X25519 and ChaCha20-Poly1305"),
]


def step(text: str) -> None:
    print(f"\n== {text}")


def fail(text: str) -> None:
    print(f"\nFAILED: {text}")
    raise SystemExit(1)


def check_python() -> None:
    step(f"Python {'.'.join(map(str, sys.version_info[:3]))}")
    if sys.version_info < MIN_PYTHON:
        fail(
            f"Python {'.'.join(map(str, MIN_PYTHON))} or newer is required.\n"
            f"  Install it from python.org, then run this script with the new one."
        )
    print(f"  ok ({sys.executable})")


def install() -> None:
    step("Installing dependencies")
    requirements = ROOT / "requirements.txt"
    if not requirements.exists():
        fail(f"{requirements} is missing -- run this from inside the repo.")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
        check=False,
    )
    if result.returncode != 0:
        fail(
            "pip could not install everything (see its output above).\n"
            "  On Windows a common cause is a missing C++ build toolchain; most\n"
            "  of these ship as wheels, so check your Python is 64-bit and current."
        )
    print("  ok")


def check_imports() -> None:
    step("Checking imports")
    missing = []
    for module, purpose in CHECKS:
        try:
            __import__(module)
        except Exception as exc:
            missing.append(f"  {module:<14} {purpose}  --  {type(exc).__name__}: {exc}")
        else:
            print(f"  ok  {module:<14} {purpose}")
    if missing:
        fail("these could not be imported even after installing:\n" + "\n".join(missing))


def check_capture() -> None:
    """Actually grab a frame. Importing mss proves nothing about permissions."""
    step("Checking screen capture")
    try:
        from common.video import Capture

        capture = Capture()
        width, height = capture.size
        print(f"  ok  {capture.backend}, {width}x{height}")
        if capture.backend.startswith("mss"):
            print("      (dxcam not in use -- works fine, just slower on Windows)")
        capture.close()
    except Exception as exc:
        print(f"  WARNING  capture failed: {type(exc).__name__}: {exc}")
        print("           You can still run viewer.py; host.py needs this working.")


def check_encoder() -> None:
    """Open a real encoder. Hardware ones only fail at open time, not import."""
    step("Checking H.264 encoder")
    try:
        import numpy as np

        from common.video import Encoder

        encoder = Encoder(320, 240)
        encoder.encode(np.zeros((240, 320, 3), dtype=np.uint8))
        print(f"  ok  {encoder.name}")
        if encoder.name == "libx264":
            print("      (software encoding -- fine at 1080p30, uses more CPU)")
        for rejected in encoder.rejected:
            print(f"      unavailable: {rejected.split(':')[0]}")
        encoder.close()
    except Exception as exc:
        fail(f"no usable H.264 encoder: {type(exc).__name__}: {exc}")


def run_selftest() -> None:
    step("Running the self-test")
    result = subprocess.run(
        [sys.executable, str(ROOT / "test_selftest.py")], cwd=ROOT, check=False
    )
    if result.returncode != 0:
        fail("the self-test did not pass (see above).")


def main() -> None:
    # line_buffering matters: without it our output is block-buffered when piped
    # to a file, and the subprocesses below flush first, so their results appear
    # above the headings that introduce them.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    print("Remote Desktop -- setup")
    check_python()
    install()
    check_imports()
    check_capture()
    check_encoder()
    run_selftest()
    print("\n" + "=" * 68)
    print("  Ready.")
    print()
    print("  On the machine you want to control:   python host.py")
    print("  On the machine you want to use:       python viewer.py")
    print()
    print("  Swap the two codes they print, check the four words match,")
    print("  and answer y to the consent prompt on the host.")
    print("=" * 68)


if __name__ == "__main__":
    main()
