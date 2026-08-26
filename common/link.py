"""The peer link: hole punching, then an encrypted UDP session over the result.

One socket carries everything -- punch probes, keepalive pings, video fragments
and the reliable input channel -- because the punched NAT mapping only exists
for that one socket. A single receive thread services it.
"""
from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable, Sequence

from common import crypto, protocol

Candidate = tuple[tuple[str, int], str]  # ((host, port), label for the HUD)

PING_INTERVAL = 0.5
LINK_TIMEOUT = 8.0

# The OS default is 64KB on Windows and most Linuxes. A single keyframe can be
# 200KB, so the default silently discards two thirds of it before the receive
# thread ever runs, and the frame can never complete.
SOCKET_BUFFER = 4 * 1024 * 1024

# Fragments per burst before yielding. A 30-fragment delta frame goes out in one
# go; a 166-fragment keyframe is spread out instead of slamming the narrowest
# hop on the path, which drops the tail of the burst and costs the whole frame.
BURST = 32
BURST_PAUSE = 0.001

# Port prediction, for when one side sits behind a symmetric NAT (typical of
# mobile data). That NAT picks a different external port per destination, so
# the port in its code is the one it uses for STUN, not for us -- and our own
# router then refuses the peer's real port because we never sent anything to it.
# Spraying a window of ports opens our filter across the range the peer's NAT
# is likely to have picked. Allocators are usually near-sequential, so a few
# hundred either side of the observed port is a genuine chance rather than a
# lottery ticket. Only starts after the honest attempt has already failed.
SPRAY_AFTER = 8.0
SPRAY_SPAN = 400
SPRAY_INTERVAL = 3.0
SPRAY_CHUNK = 64
SPRAY_PAUSE = 0.002


def new_socket(port: int = 0) -> socket.socket:
    """A UDP socket with buffers big enough for video-sized bursts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, option, SOCKET_BUFFER)
        except OSError:
            pass  # some platforms cap this; the smaller buffer still works
    sock.bind(("0.0.0.0", port))
    return sock


class PunchFailed(Exception):
    """Raised with a human-readable account of everything that was tried."""


class Link:
    """A live, authenticated session with one peer."""

    def __init__(
        self,
        sock: socket.socket,
        sealer: crypto.Sealer,
        opener: crypto.Opener,
        peer: tuple[str, int],
        fingerprint: str,
        path: str,
    ) -> None:
        self.sock = sock
        self.peer = peer
        self.fingerprint = fingerprint
        self.path = path
        self.rtt = 0.0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.frames_received = 0
        self.last_heard = time.perf_counter()

        self._sealer = sealer
        self._opener = opener
        self._lock = threading.Lock()
        self._reassembler = protocol.Reassembler()
        self._reliable = protocol.ReliableChannel(self._send)
        self._thread: threading.Thread | None = None
        self._closed = threading.Event()
        self._on_video: Callable[[bytes, bool], None] | None = None
        self._on_reliable: Callable[[bytes], None] | None = None

    # -- outbound ---------------------------------------------------------

    def _send(self, plaintext: bytes) -> None:
        with self._lock:  # the nonce counter must not be shared unguarded
            datagram = self._sealer.seal(plaintext)
            try:
                self.sock.sendto(datagram, self.peer)
            except OSError:
                return
            self.bytes_sent += len(datagram)

    def send_video(self, frame_id: int, encoded: bytes, keyframe: bool = False) -> None:
        """Fire a frame off as fragments. Never retransmitted -- a late frame is useless.

        Large frames are paced: losing any one fragment costs the entire frame,
        so a 166-fragment keyframe sent flat out is the most fragile thing this
        program does.
        """
        for index, part in enumerate(protocol.fragment(frame_id, encoded, keyframe)):
            if index and index % BURST == 0:
                time.sleep(BURST_PAUSE)
            self._send(part)

    def send_reliable(self, payload: bytes) -> None:
        """Queue an input or control message for acked, in-order delivery."""
        self._reliable.send(payload)

    # -- lifecycle --------------------------------------------------------

    def start(
        self,
        on_video: Callable[[bytes, bool], None] | None = None,
        on_reliable: Callable[[bytes], None] | None = None,
    ) -> None:
        self._on_video = on_video
        self._on_reliable = on_reliable
        self._thread = threading.Thread(target=self._run, daemon=True, name="link-rx")
        self._thread.start()

    def close(self) -> None:
        self._closed.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        self.sock.close()

    @property
    def alive(self) -> bool:
        return not self._closed.is_set() and time.perf_counter() - self.last_heard < LINK_TIMEOUT

    @property
    def dropped_frames(self) -> int:
        return self._reassembler.lost

    @property
    def stats(self) -> dict[str, object]:
        return {
            "path": self.path,
            "peer": f"{self.peer[0]}:{self.peer[1]}",
            "rtt_ms": round(self.rtt * 1000, 1),
            "frames": self.frames_received,
            "dropped_frames": self._reassembler.lost,
            "retransmits": self._reliable.retransmits,
            "rejected": self._opener.rejected,
            "sent_kb": round(self.bytes_sent / 1024),
            "recv_kb": round(self.bytes_received / 1024),
        }

    # -- inbound ----------------------------------------------------------

    def _run(self) -> None:
        self.sock.settimeout(0.1)
        next_ping = 0.0
        while not self._closed.is_set():
            now = time.perf_counter()
            if now >= next_ping:
                next_ping = now + PING_INTERVAL
                self._send(protocol.ping(now))  # doubles as the NAT keepalive
                self._reliable.tick(self.rtt)
            try:
                datagram, source = self.sock.recvfrom(protocol.MAX_DATAGRAM + 64)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            if source != self.peer:
                continue  # cheap filter; the AEAD tag below is the real check
            plaintext = self._opener.open(datagram)
            if plaintext is None:
                continue
            self.bytes_received += len(datagram)
            self.last_heard = time.perf_counter()
            self._dispatch(plaintext)

    def _dispatch(self, plaintext: bytes) -> None:
        kind = protocol.packet_type(plaintext)
        if kind == protocol.T_VIDEO:
            frame = self._reassembler.push(plaintext)
            if frame and self._on_video:
                self.frames_received += 1
                self._on_video(*frame)
        elif kind == protocol.T_REL:
            for payload in self._reliable.on_data(plaintext):
                if self._on_reliable:
                    self._on_reliable(payload)
        elif kind == protocol.T_REL_ACK:
            self._reliable.on_ack(plaintext)
        elif kind == protocol.T_PING:
            self._send(protocol.pong(plaintext))
        elif kind == protocol.T_PONG:
            self.rtt = protocol.pong_rtt(plaintext, time.perf_counter())
        elif kind == protocol.T_PUNCH:
            self._send(bytes([protocol.T_PUNCH_ACK]))  # peer is still finishing its punch


def _spray(
    sock: socket.socket,
    sealer: crypto.Sealer,
    probe: bytes,
    candidates: Sequence[Candidate],
) -> int:
    """Probe a window of ports around each public candidate. Returns how many."""
    sent = 0
    for address, label in candidates:
        if label != "WAN":
            continue  # a LAN address is never port-translated, so there is nothing to predict
        host, base = address
        for offset in range(-SPRAY_SPAN, SPRAY_SPAN + 1):
            port = base + offset
            if offset == 0 or not (1 <= port <= 65535):
                continue
            try:
                sock.sendto(sealer.seal(probe), (host, port))
            except OSError:
                continue
            sent += 1
            if sent % SPRAY_CHUNK == 0:
                time.sleep(SPRAY_PAUSE)  # do not machine-gun the carrier
    return sent


def punch(
    sock: socket.socket,
    priv,
    peer_pub: bytes,
    candidates: Sequence[Candidate],
    timeout: float = 20.0,
    on_progress: Callable[[str], None] | None = None,
) -> Link:
    """Race UDP probes at every candidate address until one answers.

    Both peers do this at once. The first probe each way is usually dropped by
    the far NAT, but it opens the near filter, so the reply gets through.
    Probes are encrypted, so anything that decrypts is provably the real peer.
    """
    send_key, recv_key, fp = crypto.derive(priv, peer_pub)
    sealer, opener = crypto.Sealer(send_key), crypto.Opener(recv_key)
    labels = {address: label for address, label in candidates}
    probe = bytes([protocol.T_PUNCH])
    started = time.perf_counter()
    deadline = started + timeout
    attempts = 0
    sprayed = 0
    last_spray = 0.0

    sock.settimeout(0.15)
    while time.perf_counter() < deadline:
        for address, _label in candidates:
            try:
                sock.sendto(sealer.seal(probe), address)
            except OSError:
                continue
        attempts += 1
        now = time.perf_counter()
        if now - started > SPRAY_AFTER and now - last_spray > SPRAY_INTERVAL:
            last_spray = now
            sprayed += _spray(sock, sealer, probe, candidates)
            if on_progress:
                on_progress(
                    f"no direct answer -- predicting ports ({sprayed} tried), "
                    f"{int(deadline - now)}s left"
                )
        elif on_progress and attempts % 10 == 1:
            on_progress(f"punching... {int(deadline - now)}s left")

        window = time.perf_counter() + 0.2
        while time.perf_counter() < window:
            try:
                datagram, source = sock.recvfrom(protocol.MAX_DATAGRAM + 64)
            except (socket.timeout, TimeoutError):
                break
            except OSError:
                break
            plaintext = opener.open(datagram)
            if not plaintext or protocol.packet_type(plaintext) not in (
                protocol.T_PUNCH,
                protocol.T_PUNCH_ACK,
            ):
                continue
            path = labels.get(source, "direct")
            for _ in range(5):  # help the far side finish its own punch
                sock.sendto(sealer.seal(bytes([protocol.T_PUNCH_ACK])), source)
            if on_progress:
                on_progress(f"connected via {path} to {source[0]}:{source[1]}")
            return Link(sock, sealer, opener, source, fp, path)

    tried = "\n".join(f"    {a[0]}:{a[1]}  ({label})" for a, label in candidates)
    raise PunchFailed(
        f"No reply from the peer after {timeout:.0f}s and {attempts} probe rounds.\n"
        f"  Candidates tried:\n{tried}\n"
        f"  Our local port: {sock.getsockname()[1]}\n"
        f"\n"
        f"  MOST LIKELY CAUSE: a stale code. Every restart binds a new random\n"
        f"  port, so a code stops working the moment the program that printed it\n"
        f"  is restarted. Check the ports listed above against what the peer's\n"
        f"  own screen reports as its address right now. If they differ, the code\n"
        f"  is from an older run -- restart both sides and swap fresh codes.\n"
        f"  Use --port to pin a fixed port if you are restarting a lot.\n"
        f"\n"
        f"  Both sides must also be punching at the same time. The host only\n"
        f"  starts once you paste the viewer's code, so do that promptly."
    )


def _loopback_demo() -> None:
    """Two links talking over 127.0.0.1 -- the smoke test for this module."""
    import os

    a_priv, a_pub = crypto.generate_keypair()
    b_priv, b_pub = crypto.generate_keypair()
    a_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    a_sock.bind(("127.0.0.1", 0))
    b_sock.bind(("127.0.0.1", 0))

    result: dict[str, Link] = {}

    def connect(name, sock, priv, peer_pub, peer_sock):
        result[name] = punch(sock, priv, peer_pub, [(peer_sock.getsockname(), "loopback")])

    threads = [
        threading.Thread(target=connect, args=("a", a_sock, a_priv, b_pub, b_sock)),
        threading.Thread(target=connect, args=("b", b_sock, b_priv, a_pub, a_sock)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    a, b = result["a"], result["b"]
    assert a.fingerprint == b.fingerprint, "peers disagree on the fingerprint"
    print(f"  connected via {a.path}, fingerprint: {a.fingerprint}")

    seen_frames: list[tuple[bytes, bool]] = []
    seen_messages: list[bytes] = []
    b.start(on_video=lambda data, key: seen_frames.append((data, key)))
    a.start(on_reliable=seen_messages.append)

    frame = os.urandom(60_000)
    a.send_video(1, frame, keyframe=True)
    for i in range(20):
        b.send_reliable(f"input-{i}".encode())

    for _ in range(100):
        if seen_frames and len(seen_messages) == 20 and a.rtt:
            break
        time.sleep(0.05)

    assert seen_frames == [(frame, True)], "video frame did not survive the link"
    assert seen_messages == [f"input-{i}".encode() for i in range(20)], "input order broken"
    assert a.rtt > 0, "no pong came back"
    print(f"  60KB frame + 20 input events delivered, rtt {a.rtt * 1000:.2f}ms")
    print(f"  stats: {a.stats}")
    a.close()
    b.close()
    print("\nlink loopback demo ok")


if __name__ == "__main__":
    _loopback_demo()
