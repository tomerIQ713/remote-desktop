"""Wire format: packet types, video fragmentation, and a small reliable channel.

Everything here works on plaintext. Sealing happens one layer down in
common.crypto, and the sizes below already leave room for its overhead.
"""
from __future__ import annotations

import struct
import time
from collections.abc import Callable, Iterator

from common import crypto

# 1200 is comfortably under every real-world path MTU, so nothing gets
# IP-fragmented on the way across the internet.
MAX_DATAGRAM = 1200
MAX_PLAINTEXT = MAX_DATAGRAM - crypto.OVERHEAD

T_PUNCH = 1
T_PUNCH_ACK = 2
T_PING = 3
T_PONG = 4
T_VIDEO = 5
T_REL = 6
T_REL_ACK = 7

FLAG_KEYFRAME = 1

_VIDEO_HDR = struct.Struct("!BIHHB")  # type, frame_id, frag_idx, frag_count, flags
_REL_HDR = struct.Struct("!BI")  # type, seq
_PING_HDR = struct.Struct("!Bd")  # type, sender timestamp

FRAG_PAYLOAD = MAX_PLAINTEXT - _VIDEO_HDR.size


def packet_type(plaintext: bytes) -> int:
    return plaintext[0]


def ping(now: float) -> bytes:
    return _PING_HDR.pack(T_PING, now)


def pong(ping_plaintext: bytes) -> bytes:
    """Echo the sender's own timestamp so it can measure RTT without a clock sync."""
    return _PING_HDR.pack(T_PONG, _PING_HDR.unpack(ping_plaintext)[1])


def pong_rtt(pong_plaintext: bytes, now: float) -> float:
    return now - _PING_HDR.unpack(pong_plaintext)[1]


def fragment(frame_id: int, data: bytes, keyframe: bool = False) -> Iterator[bytes]:
    """Split one encoded frame across as many datagrams as it needs."""
    count = max(1, -(-len(data) // FRAG_PAYLOAD))
    if count > 0xFFFF:
        raise ValueError("frame too large to fragment")
    flags = FLAG_KEYFRAME if keyframe else 0
    for i in range(count):
        chunk = data[i * FRAG_PAYLOAD : (i + 1) * FRAG_PAYLOAD]
        yield _VIDEO_HDR.pack(T_VIDEO, frame_id, i, count, flags) + chunk


class Reassembler:
    """Rebuilds frames from fragments, discarding any that arrive incomplete.

    A frame missing even one fragment decodes to garbage, so it is dropped and
    counted instead. The caller watches `lost` and asks the host for a fresh
    keyframe, which is cheaper than showing a corrupt picture.
    """

    def __init__(self, keep: int = 8) -> None:
        self._pending: dict[int, tuple[int, int, dict[int, bytes]]] = {}
        self._keep = keep
        self._delivered = 0
        self.lost = 0

    def push(self, plaintext: bytes) -> tuple[bytes, bool] | None:
        """Return (encoded frame, is_keyframe) once a frame completes."""
        if len(plaintext) < _VIDEO_HDR.size:
            return None
        _t, frame_id, idx, count, flags = _VIDEO_HDR.unpack_from(plaintext)
        if frame_id <= self._delivered or count == 0 or idx >= count:
            return None  # stale, or a malformed header

        count_seen, flags_seen, chunks = self._pending.setdefault(
            frame_id, (count, flags, {})
        )
        if count_seen != count:
            return None  # fragments disagree about the frame; ignore the odd one out
        chunks[idx] = plaintext[_VIDEO_HDR.size :]
        if len(chunks) < count:
            self._evict()
            return None

        del self._pending[frame_id]
        self._delivered = frame_id
        for older in [f for f in self._pending if f < frame_id]:
            del self._pending[older]
            self.lost += 1  # a newer frame beat it home; it will never complete
        return b"".join(chunks[i] for i in range(count)), bool(flags_seen & FLAG_KEYFRAME)

    def _evict(self) -> None:
        while len(self._pending) > self._keep:
            del self._pending[min(self._pending)]
            self.lost += 1


class ReliableChannel:
    """Sequenced, acked, in-order delivery for input and control messages.

    Input has to be both reliable and ordered -- a lost key-up leaves a modifier
    stuck down on the host. Volume is a few hundred bytes a second, so the whole
    window lives in a dict and anything unacked is simply resent on a timer.
    """

    def __init__(self, send_raw: Callable[[bytes], None]) -> None:
        self._send_raw = send_raw
        self._next_seq = 1
        self._unacked: dict[int, tuple[bytes, float]] = {}
        self._expected = 1
        self._early: dict[int, bytes] = {}
        self.retransmits = 0

    @property
    def in_flight(self) -> int:
        return len(self._unacked)

    def send(self, payload: bytes) -> None:
        seq = self._next_seq
        self._next_seq += 1
        packet = _REL_HDR.pack(T_REL, seq) + payload
        self._unacked[seq] = (packet, time.perf_counter())
        self._send_raw(packet)

    def tick(self, rtt: float) -> None:
        """Resend anything that has gone unacked for longer than the link's RTT."""
        now = time.perf_counter()
        timeout = max(0.05, rtt * 1.5)
        for seq, (packet, sent_at) in list(self._unacked.items()):
            if now - sent_at > timeout:
                self._unacked[seq] = (packet, now)
                self.retransmits += 1
                self._send_raw(packet)

    def on_data(self, plaintext: bytes) -> list[bytes]:
        """Ack the message and return whatever is now deliverable, in order."""
        if len(plaintext) < _REL_HDR.size:
            return []
        _t, seq = _REL_HDR.unpack_from(plaintext)
        self._send_raw(_REL_HDR.pack(T_REL_ACK, seq))  # ack duplicates too; the first ack may have been lost
        if seq < self._expected:
            return []
        self._early[seq] = plaintext[_REL_HDR.size :]
        ready = []
        while self._expected in self._early:
            ready.append(self._early.pop(self._expected))
            self._expected += 1
        return ready

    def on_ack(self, plaintext: bytes) -> None:
        if len(plaintext) < _REL_HDR.size:
            return
        _t, seq = _REL_HDR.unpack_from(plaintext)
        self._unacked.pop(seq, None)


# -- application messages, carried on the reliable channel -----------------

M_MOUSE_MOVE = 1
M_MOUSE_BUTTON = 2
M_MOUSE_SCROLL = 3
M_KEY = 4
M_TEXT = 5
M_KEYFRAME = 6
M_HELLO = 7
M_REPORT = 8
M_CLIPBOARD = 9

_M_MOVE = struct.Struct("!BHH")  # kind, x, y as fractions of 65535
_M_BUTTON = struct.Struct("!BBB")  # kind, button, pressed
_M_SCROLL = struct.Struct("!Bbb")  # kind, dx, dy
_M_KEY = struct.Struct("!BBI")  # kind, pressed, key id
_M_HELLO = struct.Struct("!BHHB")  # kind, screen width, height, control allowed
_M_REPORT = struct.Struct("!BIIH")  # kind, frames decoded, frames dropped, rtt in ms
_M_CLIP = struct.Struct("!BB")  # kind, more-chunks-follow

# The reliable channel does not fragment -- one message is one datagram -- so a
# clipboard has to be split by hand to stay under MAX_PLAINTEXT.
CLIP_CHUNK = 1100
CLIP_MAX = 64 * 1024  # a channel sized for keystrokes; a copied file listing must not flood it

# Key ids below 128 are the literal ASCII character to press, so no table is
# needed for the common case. 128 and up are named keys.
(
    K_ESC, K_TAB, K_BACKSPACE, K_ENTER, K_DELETE, K_INSERT, K_HOME, K_END,
    K_PAGEUP, K_PAGEDOWN, K_UP, K_DOWN, K_LEFT, K_RIGHT, K_SHIFT, K_CTRL,
    K_ALT, K_META, K_CAPSLOCK, K_PRINTSCREEN, K_MENU, K_NUMLOCK,
) = range(128, 150)
K_F1 = 150  # F1..F24 run contiguously from here


def mouse_move(x: float, y: float) -> bytes:
    """Position as a fraction of the screen, so viewer and host need not agree on size."""
    clamp = lambda v: max(0, min(65535, int(v * 65535)))  # noqa: E731
    return _M_MOVE.pack(M_MOUSE_MOVE, clamp(x), clamp(y))


def mouse_button(button: int, pressed: bool) -> bytes:
    return _M_BUTTON.pack(M_MOUSE_BUTTON, button, int(pressed))


def mouse_scroll(dx: int, dy: int) -> bytes:
    clamp = lambda v: max(-127, min(127, int(v)))  # noqa: E731
    return _M_SCROLL.pack(M_MOUSE_SCROLL, clamp(dx), clamp(dy))


def key(key_id: int, pressed: bool) -> bytes:
    return _M_KEY.pack(M_KEY, int(pressed), key_id)


def text(value: str) -> bytes:
    """Typed characters, sent as text so keyboard layouts do not have to match."""
    return bytes([M_TEXT]) + value.encode("utf-8")


def clipboard_chunks(text: str) -> list[bytes]:
    """Split a clipboard into reliable-channel messages.

    Returns an empty list for anything over CLIP_MAX, which is the caller's
    signal to skip the update rather than spend the input channel on it.
    Splitting is done on the encoded bytes, so a multi-byte character may land
    across a boundary; the far side joins before decoding, so that is fine.
    """
    data = text.encode("utf-8")
    if len(data) > CLIP_MAX:
        return []
    out = []
    for start in range(0, max(len(data), 1), CLIP_CHUNK):
        piece = data[start : start + CLIP_CHUNK]
        more = 1 if start + CLIP_CHUNK < len(data) else 0
        out.append(_M_CLIP.pack(M_CLIPBOARD, more) + piece)
    return out


class ClipboardAssembler:
    """Rebuilds a clipboard string from chunk messages.

    Bounded on purpose: this runs on data from the network, and a peer that
    never sets more=0 would otherwise grow this buffer without limit.
    """

    def __init__(self) -> None:
        self._parts: list[bytes] = []
        self._size = 0

    def push(self, more: int, chunk: bytes) -> str | None:
        """Return the finished text, or None while chunks are still outstanding."""
        self._size += len(chunk)
        if self._size > CLIP_MAX:
            self._parts.clear()  # a peer feeding us an endless clipboard; drop it
            self._size = 0
            return None
        self._parts.append(chunk)
        if more:
            return None
        text = b"".join(self._parts).decode("utf-8", "replace")
        self._parts.clear()
        self._size = 0
        return text


def keyframe_request() -> bytes:
    return bytes([M_KEYFRAME])


def hello(width: int, height: int, control_allowed: bool) -> bytes:
    return _M_HELLO.pack(M_HELLO, width, height, int(control_allowed))


def report(decoded: int, dropped: int, rtt_ms: int) -> bytes:
    return _M_REPORT.pack(M_REPORT, decoded, dropped, min(65535, rtt_ms))


_LAYOUTS = {
    M_MOUSE_MOVE: _M_MOVE,
    M_MOUSE_BUTTON: _M_BUTTON,
    M_MOUSE_SCROLL: _M_SCROLL,
    M_KEY: _M_KEY,
    M_HELLO: _M_HELLO,
    M_REPORT: _M_REPORT,
}


def decode_message(payload: bytes) -> tuple:
    """Return (kind, *fields), or (0,) for anything malformed.

    This runs on input arriving from the network, so it never raises -- a
    truncated or unknown message is dropped rather than killing the session.
    """
    if not payload:
        return (0,)
    kind = payload[0]
    if kind == M_TEXT:
        return (kind, payload[1:].decode("utf-8", "replace"))
    if kind == M_KEYFRAME:
        return (kind,)
    if kind == M_CLIPBOARD:
        if len(payload) < _M_CLIP.size:
            return (0,)
        return (kind, payload[1], payload[_M_CLIP.size :])  # bytes; joined before decoding
    layout = _LAYOUTS.get(kind)
    if layout is None or len(payload) < layout.size:
        return (0,)
    return layout.unpack_from(payload)
