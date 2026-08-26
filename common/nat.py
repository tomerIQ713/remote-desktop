"""Learning our own public address, classifying the NAT, and the connection code.

STUN is the only outside party this project talks to, and only to answer a
question nothing inside the network can: which public ip:port does the world
see this socket as? It never learns about the peer.

The classification matters because it is decidable in advance. A NAT that hands
out a different external port per destination (RFC 4787 calls this
endpoint-dependent mapping; most people call it symmetric) makes the address in
a connection code meaningless to the peer, so punching cannot work. Detecting
that up front turns a baffling timeout into a clear explanation.
"""
from __future__ import annotations

import base64
import os
import socket
import struct
import threading
import zlib
from dataclasses import dataclass

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

_MAGIC = 0x2112A442
_BINDING_REQUEST = 0x0001
_BINDING_RESPONSE = 0x0101
_XOR_MAPPED_ADDRESS = 0x0020
_MAPPED_ADDRESS = 0x0001

CODE_PREFIX = "RD1-"
_CODE = struct.Struct("!BB4sH4sH32s")  # version, flags, pub ip/port, lan ip/port, pubkey
_VERSION = 1
_FLAG_HAS_PUBLIC = 1


class StunError(Exception):
    pass


class BadCode(ValueError):
    pass


# -- STUN ------------------------------------------------------------------


def _parse_binding_response(data: bytes, transaction: bytes) -> tuple[str, int]:
    if len(data) < 20:
        raise StunError("runt STUN response")
    kind, length, magic, txn = struct.unpack("!HHI12s", data[:20])
    if kind != _BINDING_RESPONSE or magic != _MAGIC:
        raise StunError(f"not a STUN binding response (type 0x{kind:04x})")
    if txn != transaction:
        raise StunError("STUN transaction id mismatch")

    offset, end = 20, min(len(data), 20 + length)
    while offset + 4 <= end:
        attr, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        value = data[offset + 4 : offset + 4 + attr_len]
        offset += 4 + attr_len + (-attr_len % 4)  # attributes are padded to 4 bytes
        if attr not in (_XOR_MAPPED_ADDRESS, _MAPPED_ADDRESS) or len(value) < 8:
            continue
        family, port = struct.unpack("!xBH", value[:4])
        if family != 0x01:
            continue  # IPv6; this project punches over IPv4
        address = value[4:8]
        if attr == _XOR_MAPPED_ADDRESS:
            port ^= _MAGIC >> 16
            address = bytes(b ^ m for b, m in zip(address, struct.pack("!I", _MAGIC)))
        return socket.inet_ntoa(address), port
    raise StunError("STUN response carried no mapped address")


def stun_query(
    sock: socket.socket, server: tuple[str, int], attempts: int = 3, timeout: float = 0.4
) -> tuple[str, int]:
    """Ask one STUN server how it sees `sock`. Returns the public (ip, port)."""
    try:
        resolved = (socket.gethostbyname(server[0]), server[1])
    except OSError as exc:
        raise StunError(f"cannot resolve {server[0]}: {exc}") from exc

    previous = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        for _ in range(attempts):
            transaction = os.urandom(12)
            request = struct.pack("!HHI12s", _BINDING_REQUEST, 0, _MAGIC, transaction)
            try:
                sock.sendto(request, resolved)
            except OSError as exc:
                raise StunError(f"cannot reach {server[0]}: {exc}") from exc
            try:
                data, source = sock.recvfrom(2048)
            except (socket.timeout, TimeoutError):
                continue
            if source != resolved:
                continue  # some other traffic on this socket; keep waiting
            return _parse_binding_response(data, transaction)
        raise StunError(f"no response from {server[0]}:{server[1]} after {attempts} tries")
    finally:
        sock.settimeout(previous)


def local_address(sock: socket.socket) -> tuple[str, int]:
    """The LAN ip:port of this socket. Lets two peers on one network skip the internet."""
    port = sock.getsockname()[1]
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))  # no packet is sent; this just picks a route
        return probe.getsockname()[0], port
    except OSError:
        return "127.0.0.1", port
    finally:
        probe.close()


# -- NAT classification ----------------------------------------------------


@dataclass
class NatReport:
    public: tuple[str, int] | None
    lan: tuple[str, int]
    observations: list[tuple[str, tuple[str, int] | str]]
    behavior: str
    punchable: bool

    def explain(self) -> str:
        lines = [f"  LAN address:    {self.lan[0]}:{self.lan[1]}"]
        if self.public:
            lines.append(f"  Public address: {self.public[0]}:{self.public[1]}")
        else:
            lines.append("  Public address: unknown -- every STUN server failed")
        for server, seen in self.observations:
            lines.append(f"    via {server:<28} {seen if isinstance(seen, str) else f'{seen[0]}:{seen[1]}'}")
        lines.append(f"  NAT behavior:   {self.behavior}")
        if self.punchable:
            lines.append("  Verdict:        punchable -- this side is fine")
        else:
            lines.append("  Verdict:        NOT punchable from this network")
            lines.append("                  Your router assigns a different public port per")
            lines.append("                  destination, so the address in your code is not the")
            lines.append("                  one your peer would need. Try a different network")
            lines.append("                  (mobile hotspot, or off carrier-grade NAT), or set a")
            lines.append("                  relay if you ever have a server to run one on.")
        return "\n".join(lines)


def probe(sock: socket.socket, servers: list[tuple[str, int]] | None = None) -> NatReport:
    """Classify this socket's NAT by asking two servers what port they see.

    Same port from both means endpoint-independent mapping, which is what
    hole punching needs. Different ports means it cannot work.
    """
    servers = servers or STUN_SERVERS
    lan = local_address(sock)
    observations: list[tuple[str, tuple[str, int] | str]] = []
    seen: list[tuple[str, int]] = []

    for server in servers:
        name = f"{server[0]}:{server[1]}"
        try:
            result = stun_query(sock, server)
            observations.append((name, result))
            seen.append(result)
        except StunError as exc:
            observations.append((name, f"failed ({exc})"))
        if len(seen) >= 2:
            break  # two agreeing samples is all the classification needs

    if not seen:
        return NatReport(None, lan, observations, "unknown -- no STUN server answered", False)
    public = seen[0]
    if len(seen) == 1:
        return NatReport(public, lan, observations, "unverified -- only one server answered", True)
    if len({p for _ip, p in seen}) == 1 and len({ip for ip, _p in seen}) == 1:
        if public == lan:
            return NatReport(public, lan, observations, "open internet -- no NAT", True)
        return NatReport(public, lan, observations, "endpoint-independent mapping", True)
    return NatReport(
        public, lan, observations, "endpoint-dependent mapping (symmetric NAT)", False
    )


# -- connection codes ------------------------------------------------------


@dataclass
class Code:
    """What one peer must tell the other: where to find it and who it is."""

    lan: tuple[str, int]
    pubkey: bytes
    public: tuple[str, int] | None = None

    def encode(self) -> str:
        flags = _FLAG_HAS_PUBLIC if self.public else 0
        public = self.public or ("0.0.0.0", 0)
        body = _CODE.pack(
            _VERSION,
            flags,
            socket.inet_aton(public[0]),
            public[1],
            socket.inet_aton(self.lan[0]),
            self.lan[1],
            self.pubkey,
        )
        checksum = struct.pack("!H", zlib.crc32(body) & 0xFFFF)
        return CODE_PREFIX + base64.urlsafe_b64encode(body + checksum).decode().rstrip("=")

    @staticmethod
    def decode(text: str) -> Code:
        cleaned = "".join(text.split())
        if cleaned.upper().startswith(CODE_PREFIX):
            cleaned = cleaned[len(CODE_PREFIX) :]
        if not cleaned:
            raise BadCode("empty code")
        try:
            raw = base64.urlsafe_b64decode(cleaned + "=" * (-len(cleaned) % 4))
        except Exception as exc:
            raise BadCode(f"not valid code text: {exc}") from exc
        if len(raw) != _CODE.size + 2:
            raise BadCode(
                f"code is {len(raw)} bytes, expected {_CODE.size + 2} -- it looks truncated"
            )
        body, checksum = raw[: _CODE.size], raw[_CODE.size :]
        if struct.unpack("!H", checksum)[0] != zlib.crc32(body) & 0xFFFF:
            raise BadCode("checksum mismatch -- the code was altered or copied incompletely")
        version, flags, pub_ip, pub_port, lan_ip, lan_port, pubkey = _CODE.unpack(body)
        if version != _VERSION:
            raise BadCode(f"code is version {version}, this build speaks {_VERSION}")
        public = (socket.inet_ntoa(pub_ip), pub_port) if flags & _FLAG_HAS_PUBLIC else None
        return Code((socket.inet_ntoa(lan_ip), lan_port), pubkey, public)

    def candidates(self) -> list[tuple[tuple[str, int], str]]:
        """Addresses to punch at, LAN first so a same-network peer connects instantly."""
        found = [(self.lan, "LAN")]
        if self.public:
            found.append((self.public, "WAN"))
        return found


class MappingKeepalive:
    """Re-STUNs periodically so the NAT mapping in our code stays valid.

    Routers drop idle UDP mappings after 30s-2min. Since a human is off copying
    the code into a chat window, the port printed a minute ago would otherwise
    be closed by the time the peer aims at it.
    """

    def __init__(self, sock: socket.socket, interval: float = 15.0) -> None:
        self._sock = sock
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="nat-keepalive")

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                stun_query(self._sock, STUN_SERVERS[0], attempts=1)
            except StunError:
                pass  # a missed refresh is not fatal; the next one may land

    def __enter__(self) -> MappingKeepalive:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=1.0)


def gather(sock: socket.socket, pubkey: bytes) -> tuple[Code, NatReport]:
    """Everything a peer needs about this socket, plus why it might not work."""
    report = probe(sock)
    return Code(report.lan, pubkey, report.public), report


if __name__ == "__main__":
    from common import crypto

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    _priv, pub = crypto.generate_keypair()
    code, report = gather(sock, pub)
    print(report.explain())
    print(f"\n  code ({len(code.encode())} chars):\n  {code.encode()}")
    assert Code.decode(code.encode()) == code, "code did not survive a round trip"
    print("\nnat probe ok")
    sock.close()
