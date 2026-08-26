"""Authenticated encryption and the X25519 handshake for a peer link.

Both peers derive the same key material from one ECDH exchange, then use a
separate key per direction so their nonce counters can never collide.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_LEN = 12
TAG_LEN = 16
OVERHEAD = NONCE_LEN + TAG_LEN
PUBKEY_LEN = 32
WINDOW = 64  # replay window, in packets

# 128 words -> 7 bits each -> a 4-word fingerprint carries 28 bits.
_WORDS = (
    "acid actor agent album alert alpha amber anvil apple arena armor arrow aspen atlas audio axis "
    "bacon badge bagel baker banjo barge basil batch beach beacon beam bench berry bison blade bloom "
    "board bonus boost brace brave bread brick bridge brisk bronze brush cabin cable cactus canal candle "
    "canoe canvas canyon carbon cargo carve cedar chalk charm chase cheer chess chill cider cinema civic "
    "clamp clash clever cliff cloud clover cobalt cocoa comet coral cosmic cotton coyote crane crate creek "
    "crisp crown crystal cube curve cycle dagger dairy dandy dapper dawn debris decoy delta denim depot "
    "desert diamond digit dinner ditch dock dolphin domain donor draft dragon drift drum dune dusk eagle "
    "earth ember empire energy engine ethic evening exile fabric falcon feather fern fiber field flame flint"
).split()
assert len(_WORDS) == 128, len(_WORDS)


def generate_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Return (private key, 32 raw public bytes to put in the connection code)."""
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def derive(priv: X25519PrivateKey, peer_pub: bytes) -> tuple[bytes, bytes, str]:
    """Return (send_key, recv_key, fingerprint).

    Which peer gets which direction key is decided by comparing the raw public
    keys, so both ends agree without exchanging an extra message.
    """
    if len(peer_pub) != PUBKEY_LEN:
        raise ValueError(f"peer public key must be {PUBKEY_LEN} bytes")
    my_pub = priv.public_key().public_bytes_raw()
    if my_pub == peer_pub:
        raise ValueError("peer public key is our own -- codes were crossed")
    shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    lo, hi = sorted((my_pub, peer_pub))
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=68,
        salt=lo + hi,
        info=b"remote-desktop v1",
    ).derive(shared)
    lo_to_hi, hi_to_lo, fp = okm[:32], okm[32:64], okm[64:]
    if my_pub == lo:
        return lo_to_hi, hi_to_lo, fingerprint(fp)
    return hi_to_lo, lo_to_hi, fingerprint(fp)


def fingerprint(material: bytes) -> str:
    """Four words both peers can read aloud to confirm nobody altered the codes."""
    n = int.from_bytes(material[:4], "big")
    return " ".join(_WORDS[(n >> (7 * i)) & 127] for i in range(4))


class Sealer:
    """Encrypts outbound datagrams under a monotonically increasing nonce."""

    def __init__(self, key: bytes) -> None:
        self._aead = ChaCha20Poly1305(key)
        self._counter = 0

    def seal(self, plaintext: bytes) -> bytes:
        self._counter += 1
        nonce = b"\0\0\0\0" + struct.pack("!Q", self._counter)
        return nonce + self._aead.encrypt(nonce, plaintext, None)


class Opener:
    """Decrypts inbound datagrams, rejecting forgeries and replays.

    The replay window matters: without it a captured input packet could be
    resent to the host later and would move the real mouse.
    """

    def __init__(self, key: bytes) -> None:
        self._aead = ChaCha20Poly1305(key)
        self._top = 0
        self._bits = 0
        self.rejected = 0

    def open(self, datagram: bytes) -> bytes | None:
        """Return the plaintext, or None if the datagram is junk, forged or replayed."""
        if len(datagram) <= OVERHEAD:
            self.rejected += 1
            return None
        nonce, body = datagram[:NONCE_LEN], datagram[NONCE_LEN:]
        counter = struct.unpack("!Q", nonce[4:])[0]
        if self._stale(counter):
            self.rejected += 1
            return None
        try:
            plaintext = self._aead.decrypt(nonce, body, None)
        except Exception:
            self.rejected += 1
            return None
        self._mark(counter)  # only after the tag verifies, so forgeries cannot poison the window
        return plaintext

    def _stale(self, counter: int) -> bool:
        if counter == 0:
            return True
        if counter > self._top:
            return False
        if counter <= self._top - WINDOW:
            return True
        return bool(self._bits >> (self._top - counter) & 1)

    def _mark(self, counter: int) -> None:
        if counter > self._top:
            shift = counter - self._top
            mask = (1 << WINDOW) - 1
            self._bits = 1 if shift >= WINDOW else ((self._bits << shift) | 1) & mask
            self._top = counter
        else:
            self._bits |= 1 << (self._top - counter)
