"""End-to-end check: run the real host.py, connect to it, decode its screen.

This drives the whole stack -- NAT probe, code exchange, hole punch, capture,
H.264 encode, fragmentation, encryption, reassembly, decode -- against a live
host process.

It deliberately never sends mouse or keyboard input: that would seize the
desktop of whoever runs the test. The reliable input channel is proven instead
by asking for a keyframe and watching one come back, which travels the same
path as an input event.

    python test_endtoend.py
"""
from __future__ import annotations

import re
import socket
import subprocess
import sys
import threading
import time

from common import crypto, link, nat, protocol, video

CODE_PATTERN = re.compile(r"(RD1-[A-Za-z0-9_\-]+)")
HOST_ARGS = [sys.executable, "-u", "host.py", "--yes", "--fps", "10", "--max-width", "640", "--bitrate", "1000000"]


def _reader(stream, sink: list[str], done: threading.Event) -> None:
    for line in stream:
        sink.append(line.rstrip("\n"))
    done.set()


def _wait_for_code(lines: list[str], deadline: float) -> str:
    while time.perf_counter() < deadline:
        for line in list(lines):
            found = CODE_PATTERN.search(line)
            if found:
                return found.group(1)
        time.sleep(0.1)
    raise AssertionError("host never printed a connection code:\n  " + "\n  ".join(lines))


def main() -> None:
    host = subprocess.Popen(
        HOST_ARGS, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    lines: list[str] = []
    finished = threading.Event()
    threading.Thread(target=_reader, args=(host.stdout, lines, finished), daemon=True).start()

    established: link.Link | None = None
    try:
        host_code = nat.Code.decode(_wait_for_code(lines, time.perf_counter() + 40))
        print(f"  host code received, candidates: {[f'{a[0]}:{a[1]} ({l})' for a, l in host_code.candidates()]}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        priv, pubkey = crypto.generate_keypair()
        our_code, report = nat.gather(sock, pubkey)
        assert report.punchable, f"this network cannot punch:\n{report.explain()}"

        host.stdin.write(our_code.encode() + "\n")
        host.stdin.flush()

        established = link.punch(sock, priv, host_code.pubkey, host_code.candidates(), timeout=30)
        print(f"  connected via {established.path} to {established.peer[0]}:{established.peer[1]}")
        print(f"  fingerprint: {established.fingerprint}")

        decoder = video.Decoder()
        decoded: list[tuple[int, int]] = []
        keyframes = [0]
        seen_keyframe = threading.Event()
        hello: list[tuple] = []

        def on_video(encoded: bytes, is_keyframe: bool) -> None:
            if is_keyframe:
                keyframes[0] += 1
                seen_keyframe.set()
            if not seen_keyframe.is_set():
                return
            for frame in decoder.decode(encoded):
                decoded.append(frame.shape[:2])

        def on_reliable(payload: bytes) -> None:
            message = protocol.decode_message(payload)
            if message[0] == protocol.M_HELLO:
                hello.append(message)

        established.start(on_video=on_video, on_reliable=on_reliable)
        established.send_reliable(protocol.keyframe_request())

        deadline = time.perf_counter() + 25
        while time.perf_counter() < deadline and len(decoded) < 15:
            time.sleep(0.1)

        assert hello, "the host never sent its HELLO over the reliable channel"
        _kind, width, height, control = hello[0]
        print(f"  host announced {width}x{height}, control={'on' if control else 'off'}")
        assert len(decoded) >= 15, f"only {len(decoded)} frames decoded in 25s"
        assert len(set(decoded)) == 1, f"frame size changed mid-stream: {set(decoded)}"
        assert decoded[0] == (height, width), f"decoded {decoded[0]}, host announced {(height, width)}"
        assert established.rtt > 0, "no round-trip time was ever measured"

        # The keyframe we asked for came back over the same reliable channel an
        # input event would use, which is the point of this part of the test.
        before = keyframes[0]
        established.send_reliable(protocol.keyframe_request())
        extra_deadline = time.perf_counter() + 10
        while time.perf_counter() < extra_deadline and keyframes[0] <= before:
            time.sleep(0.1)
        assert keyframes[0] > before, "the host ignored a keyframe request"

        print(f"  {len(decoded)} frames decoded at {decoded[0][1]}x{decoded[0][0]}, {keyframes[0]} keyframes")
        print(f"  stats: {established.stats}")
        print("\nend-to-end ok")
    finally:
        if established:
            established.close()
        host.terminate()
        try:
            host.wait(timeout=5)
        except subprocess.TimeoutExpired:
            host.kill()


if __name__ == "__main__":
    main()
