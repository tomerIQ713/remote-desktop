"""Runnable checks for the logic that would otherwise fail silently.

No framework on purpose: `python test_selftest.py`.
"""
from __future__ import annotations

import os
import random

from common import crypto, nat, protocol


def test_handshake_agrees():
    a_priv, a_pub = crypto.generate_keypair()
    b_priv, b_pub = crypto.generate_keypair()
    a_send, a_recv, a_fp = crypto.derive(a_priv, b_pub)
    b_send, b_recv, b_fp = crypto.derive(b_priv, a_pub)

    assert a_send == b_recv and a_recv == b_send, "direction keys must cross over"
    assert a_send != a_recv, "each direction needs its own key"
    assert a_fp == b_fp, "both peers must show the same fingerprint"
    assert len(a_fp.split()) == 4


def test_fingerprint_detects_a_swapped_key():
    a_priv, a_pub = crypto.generate_keypair()
    b_priv, b_pub = crypto.generate_keypair()
    _, _, honest = crypto.derive(a_priv, b_pub)
    mitm_priv, _ = crypto.generate_keypair()
    _, _, tampered = crypto.derive(a_priv, mitm_priv.public_key().public_bytes_raw())
    assert honest != tampered, "a substituted key must change the words"


def test_seal_open_roundtrip():
    key = os.urandom(32)
    sealer, opener = crypto.Sealer(key), crypto.Opener(key)
    for i in range(200):
        message = os.urandom(random.randrange(1, 900))
        assert opener.open(sealer.seal(message)) == message, f"roundtrip failed at {i}"


def test_tampering_is_rejected():
    key = os.urandom(32)
    sealer, opener = crypto.Sealer(key), crypto.Opener(key)
    sealed = bytearray(sealer.seal(b"move the mouse to 0,0"))
    sealed[-1] ^= 0x01
    assert opener.open(bytes(sealed)) is None, "a flipped tag bit must be caught"
    assert opener.open(b"") is None and opener.open(b"short") is None

    other = crypto.Sealer(os.urandom(32))
    assert opener.open(other.seal(b"forged")) is None, "wrong key must not open"


def test_replay_is_rejected():
    key = os.urandom(32)
    sealer, opener = crypto.Sealer(key), crypto.Opener(key)
    captured = sealer.seal(b"click")
    assert opener.open(captured) == b"click"
    assert opener.open(captured) is None, "the same datagram must not open twice"

    # Reordering inside the window is fine; anything older than it is refused.
    packets = [sealer.seal(bytes([i])) for i in range(crypto.WINDOW + 20)]
    late = packets.pop(0)
    random.shuffle(packets)
    for packet in packets:
        opener.open(packet)
    assert opener.open(late) is None, "a packet older than the window must be refused"


def test_forgery_cannot_poison_the_replay_window():
    key = os.urandom(32)
    sealer, opener = crypto.Sealer(key), crypto.Opener(key)
    for _ in range(5):
        sealer.seal(b"skipped")  # burn counters so the forgery lands ahead of us
    genuine = sealer.seal(b"real")
    forged = bytearray(genuine)
    forged[-1] ^= 0xFF
    assert opener.open(bytes(forged)) is None
    assert opener.open(genuine) == b"real", "a rejected forgery must not block the real packet"


def test_fragment_roundtrip():
    for size in (1, protocol.FRAG_PAYLOAD, protocol.FRAG_PAYLOAD + 1, 40_000):
        frame = os.urandom(size)
        reassembler = protocol.Reassembler()
        out = None
        parts = list(protocol.fragment(1, frame, keyframe=True))
        assert all(len(p) <= protocol.MAX_PLAINTEXT for p in parts), "fragment exceeds MTU budget"
        for part in parts:
            out = reassembler.push(part) or out
        assert out == (frame, True), f"failed to rebuild a {size}-byte frame"
        assert reassembler.lost == 0


def test_fragments_rebuild_out_of_order():
    frame = os.urandom(20_000)
    parts = list(protocol.fragment(7, frame))
    random.shuffle(parts)
    reassembler = protocol.Reassembler()
    out = None
    for part in parts:
        out = reassembler.push(part) or out
    assert out == (frame, False)


def test_incomplete_frame_is_dropped_and_counted():
    reassembler = protocol.Reassembler()
    damaged = list(protocol.fragment(1, os.urandom(20_000)))[:-1]  # lose the last fragment
    for part in damaged:
        assert reassembler.push(part) is None
    assert reassembler.lost == 0, "not lost yet -- the tail could still arrive"

    good = os.urandom(5_000)
    out = None
    for part in protocol.fragment(2, good):
        out = reassembler.push(part) or out
    assert out == (good, False), "a later frame must still get through"
    assert reassembler.lost == 1, "the abandoned frame must be reported so we can ask for a keyframe"

    stale = list(protocol.fragment(1, os.urandom(100)))
    assert all(reassembler.push(p) is None for p in stale), "frames older than the last delivered are stale"


def test_reassembler_bounds_its_memory():
    reassembler = protocol.Reassembler(keep=4)
    for frame_id in range(1, 60):
        for part in list(protocol.fragment(frame_id, os.urandom(20_000)))[:-1]:
            reassembler.push(part)
    assert len(reassembler._pending) <= 5, "pending frames must not grow without bound"


class _Wire:
    """A lossy, reordering link between two ReliableChannels."""

    def __init__(self, loss: float = 0.0) -> None:
        self.loss = loss
        self.queue: list[tuple[str, bytes]] = []

    def sender(self, target: str):
        def send(packet: bytes) -> None:
            if random.random() >= self.loss:
                self.queue.append((target, packet))

        return send

    def flush(self, a: protocol.ReliableChannel, b: protocol.ReliableChannel) -> list[bytes]:
        delivered = []
        random.shuffle(self.queue)
        batch, self.queue = self.queue, []
        for target, packet in batch:
            channel = a if target == "a" else b
            if protocol.packet_type(packet) == protocol.T_REL:
                delivered += channel.on_data(packet)
            else:
                channel.on_ack(packet)
        return delivered


def test_reliable_channel_delivers_in_order_despite_loss():
    random.seed(1234)
    wire = _Wire(loss=0.3)
    a = protocol.ReliableChannel(wire.sender("b"))
    b = protocol.ReliableChannel(wire.sender("a"))

    messages = [f"event-{i}".encode() for i in range(50)]
    for message in messages:
        a.send(message)

    received = []
    for _ in range(200):
        received += wire.flush(a, b)
        a.tick(rtt=0.0)  # timeout floors at 50ms, so drive retransmits directly
        for seq, (packet, _sent) in list(a._unacked.items()):
            a._unacked[seq] = (packet, 0.0)
        if not wire.queue and not a.in_flight:
            break

    assert received == messages, "messages must arrive exactly once, in order"
    assert a.in_flight == 0, "everything should end up acked"
    assert a.retransmits > 0, "the lossy wire should have forced retransmits"


def test_duplicate_delivery_is_suppressed():
    wire = _Wire()
    a = protocol.ReliableChannel(wire.sender("b"))
    b = protocol.ReliableChannel(wire.sender("a"))
    a.send(b"once")
    packet = wire.queue[0][1]
    assert b.on_data(packet) == [b"once"]
    assert b.on_data(packet) == [], "a duplicate must not be delivered twice"


def test_ping_measures_rtt():
    sent_at = 100.0
    reply = protocol.pong(protocol.ping(sent_at))
    assert protocol.packet_type(reply) == protocol.T_PONG
    assert abs(protocol.pong_rtt(reply, sent_at + 0.042) - 0.042) < 1e-9


def _stun_response(transaction: bytes, ip: str, port: int, xor: bool = True) -> bytes:
    import socket as s
    import struct

    if xor:
        wire_port = port ^ (nat._MAGIC >> 16)
        wire_ip = bytes(b ^ m for b, m in zip(s.inet_aton(ip), struct.pack("!I", nat._MAGIC)))
        attr_type = nat._XOR_MAPPED_ADDRESS
    else:
        wire_port, wire_ip, attr_type = port, s.inet_aton(ip), nat._MAPPED_ADDRESS
    value = struct.pack("!xBH", 0x01, wire_port) + wire_ip
    attribute = struct.pack("!HH", attr_type, len(value)) + value
    return struct.pack("!HHI12s", nat._BINDING_RESPONSE, len(attribute), nat._MAGIC, transaction) + attribute


def test_stun_parses_xor_mapped_address():
    txn = os.urandom(12)
    got = nat._parse_binding_response(_stun_response(txn, "203.0.113.9", 51234), txn)
    assert got == ("203.0.113.9", 51234), got


def test_stun_parses_legacy_mapped_address():
    txn = os.urandom(12)
    got = nat._parse_binding_response(_stun_response(txn, "198.51.100.7", 3478, xor=False), txn)
    assert got == ("198.51.100.7", 3478), got


def test_stun_rejects_mismatched_or_malformed_responses():
    txn = os.urandom(12)
    response = _stun_response(txn, "203.0.113.9", 51234)
    for bad, why in [
        (response, "a reply for someone else's transaction"),
        (b"\x00" * 20, "a non-response message type"),
        (response[:12], "a truncated header"),
    ]:
        wrong_txn = os.urandom(12) if bad is response else txn
        try:
            nat._parse_binding_response(bad, wrong_txn)
        except nat.StunError:
            continue
        raise AssertionError(f"accepted {why}")


def test_code_roundtrip():
    _priv, pubkey = crypto.generate_keypair()
    for public in [("203.0.113.64", 56838), None]:
        code = nat.Code(lan=("192.168.1.20", 40001), pubkey=pubkey, public=public)
        text = code.encode()
        assert text.startswith(nat.CODE_PREFIX)
        assert nat.Code.decode(text) == code, f"round trip failed for public={public}"
        # tolerate what a paste really looks like: stray whitespace, prefix in any case
        messy = f"  {nat.CODE_PREFIX.lower()}{text[len(nat.CODE_PREFIX):]}\n"
        assert nat.Code.decode(messy) == code, "a realistically messy paste must still decode"


def test_code_candidates_try_lan_first():
    _priv, pubkey = crypto.generate_keypair()
    code = nat.Code(("192.168.1.20", 40001), pubkey, ("203.0.113.64", 56838))
    assert [label for _address, label in code.candidates()] == ["LAN", "WAN"]


def test_damaged_codes_are_refused():
    _priv, pubkey = crypto.generate_keypair()
    text = nat.Code(("192.168.1.20", 40001), pubkey, ("203.0.113.64", 56838)).encode()
    body = text[len(nat.CODE_PREFIX) :]
    swapped = "A" if body[5] != "A" else "B"
    damaged = {
        "a flipped character": nat.CODE_PREFIX + body[:5] + swapped + body[6:],
        "a truncated code": text[:-6],
        "an empty code": nat.CODE_PREFIX,
        "junk": "hello there",
    }
    for why, bad in damaged.items():
        try:
            nat.Code.decode(bad)
        except nat.BadCode:
            continue
        raise AssertionError(f"accepted {why} instead of reporting it")


def test_clipboard_survives_chunking():
    """A clipboard bigger than one datagram must rebuild byte-for-byte."""
    text = "".join(chr(0x400 + (i % 200)) for i in range(4000))  # multi-byte, spans chunks
    chunks = protocol.clipboard_chunks(text)
    assert len(chunks) > 1, "test text is too small to exercise chunking"
    for chunk in chunks:
        assert len(chunk) <= protocol.MAX_PLAINTEXT, "a chunk would be IP-fragmented"

    assembler = protocol.ClipboardAssembler()
    rebuilt = None
    for chunk in chunks:
        kind, more, data = protocol.decode_message(chunk)
        assert kind == protocol.M_CLIPBOARD
        rebuilt = assembler.push(more, data)
    assert rebuilt == text, "clipboard did not survive the round trip"


def test_clipboard_is_bounded_in_both_directions():
    """Neither a huge local copy nor a peer that never stops may run us out of memory."""
    assert protocol.clipboard_chunks("x" * (protocol.CLIP_MAX + 1)) == [], "oversize clipboard was not refused"

    assembler = protocol.ClipboardAssembler()
    filler = b"z" * protocol.CLIP_CHUNK
    for _ in range((protocol.CLIP_MAX // protocol.CLIP_CHUNK) + 5):
        assert assembler.push(1, filler) is None  # a peer that never sets more=0
    assert assembler._size <= protocol.CLIP_MAX, "assembler grew past its own bound"


def test_clicking_the_video_sends_a_move_and_a_button():
    """event.position() is a QPointF; QRect.contains refuses one and the whole
    viewer aborts on the first click. Needs a real widget to catch it."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QEvent, QObject, QPointF, QRect, Qt
    from PySide6.QtGui import QMouseEvent
    from PySide6.QtWidgets import QApplication

    import viewer

    app = QApplication.instance() or QApplication([])

    class _Backend(viewer.Backend):
        def __init__(self):
            QObject.__init__(self)  # no socket, no network
            self.link = None
            self.control_allowed = True
            self.sent = []

        def send(self, payload):
            self.sent.append(payload)

    backend = _Backend()
    canvas = viewer.VideoCanvas(backend)
    canvas.resize(800, 600)
    canvas._target = QRect(0, 0, 800, 600)  # what paintEvent sets once a frame lands

    for spot, expected in (((400.0, 300.0), 2), ((799.9, 599.9), 4)):  # centre, then the far corner
        app.sendEvent(canvas, QMouseEvent(
            QEvent.MouseButtonPress, QPointF(*spot), QPointF(*spot),
            Qt.LeftButton, Qt.LeftButton, Qt.NoModifier,
        ))
        assert len(backend.sent) == expected, f"click at {spot} sent {len(backend.sent)} messages"

    kinds = [protocol.decode_message(m)[0] for m in backend.sent[:2]]
    assert kinds == [protocol.M_MOUSE_MOVE, protocol.M_MOUSE_BUTTON], kinds


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
        print(f"  ok  {test.__name__}")
    print(f"\n{len(tests)} checks passed")
