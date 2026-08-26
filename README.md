# Remote Desktop

A peer-to-peer remote desktop in Python. One machine shares its screen as H.264
over UDP; the other decodes it and sends mouse and keyboard input back.

There is no server. Not a rented one, not a rendezvous service, not a relay.
The two machines find each other by exchanging a short code and punching a hole
straight through both NATs, and everything after that flows directly between
them, encrypted end to end.

```
host.py                                                        viewer.py
  dxcam / mss                                              PySide6 canvas
      |                                                             ^
   H.264 (libx264, zerolatency, no B-frames)          H.264 decode (PyAV)
      |                                                             |
   fragment  ->  ChaCha20-Poly1305  ->  UDP  ===  UDP  ->  reassemble
      ^                                                             |
   pynput injection  <-  reliable channel  <-------------  your input
```

## Running it

```bash
pip install av opencv-python numpy mss pynput PySide6 cryptography dxcam
```

`dxcam` is Windows-only and optional; without it capture falls back to `mss`.

On the machine you want to control:

```bash
python host.py
```

On the machine you want to control it from:

```bash
python viewer.py
```

Each side prints a connection code. Send the host's code to the viewer, paste it
in, and the viewer prints its own code — send that one back to the host and press
Enter. Two copy-pastes, over any channel you like: the codes are safe to post in
a group chat.

Both ends then display four words. **Check they match.** If they do, the link is
end-to-end encrypted to the peer you think it is. If they differ, someone
altered a code in transit — hang up.

Skip the retyping if you already have the host's code:

```bash
python viewer.py --code RD1-...
```

## Why the codes are the way they are

A code is 68 characters and carries the sender's public `ip:port`, its LAN
`ip:port`, an X25519 public key, and a checksum.

* **Two addresses** so that two machines on the same network connect over the LAN
  instantly, without their traffic ever leaving the building. Both candidates are
  raced and the first to answer wins; the viewer's overlay shows which path you got.
* **A public key**, not a password. The two keys produce a shared secret by ECDH,
  which becomes one ChaCha20-Poly1305 key per direction. Nothing to invent, type,
  or leak — and the four displayed words are a fingerprint of that secret, which is
  what makes tampering with a code visible.
* **A checksum**, so a truncated paste says "this code looks truncated" instead of
  timing out mysteriously.

The host process must stay running from the moment it prints its code: the public
port only exists while that socket is open. Both sides re-ping STUN every 15
seconds while waiting, because home routers close idle UDP mappings after 30
seconds to two minutes, which is well within the time it takes a human to copy a
code into a chat window.

## When it will not work

Some networks — carrier-grade NAT, most mobile data, some corporate Wi-Fi —
assign a *different* public port per destination. The address in your code is
then meaningless to your peer, and no amount of punching will help.

Both programs detect this before trying, by asking two different STUN servers
what port they see and comparing. If the answers disagree, you get told exactly
that, along with what each server reported, instead of a blank 90-second
timeout. Move to a different network, or point the design at a relay if you ever
have a server to run one on.

STUN is the one thing here that talks to the outside world. It is unavoidable:
nothing inside your network can tell you which public port your router picked.
The request is 20 bytes, it reveals only the public address you already show
every website you visit, and the STUN server never learns anything about your peer.

## Safety

This program moves a real mouse and presses real keys on the host, so:

* The host **asks before accepting any input**, showing the fingerprint words so
  you know who you are letting in. `--view-only` refuses input permanently.
* Screen capture does not open until after you consent. Nothing is grabbed, even
  into memory, before you say yes.
* **Kill switch: Ctrl+Alt+Shift+K on the host** cuts input instantly and releases
  anything currently held down. (The hotkey listener also sees injected keys, so
  the remote side can trigger it too — that is deliberate, either end can stop it.)
* Every datagram is authenticated, so forged packets are dropped rather than
  executed. Counter nonces plus a 64-packet replay window mean a captured input
  packet cannot be resent to the host later.
* Keys held when a session ends are always released, so a dropped key-up cannot
  leave Ctrl stuck down.

## The protocol

UDP, every datagram sealed with ChaCha20-Poly1305, payloads capped at 1200 bytes
so nothing is IP-fragmented in transit.

**Video** is fragmented across datagrams with a frame id and fragment index. A
frame missing any fragment is discarded, never displayed, and the viewer asks for
a fresh keyframe. Nothing is retransmitted — a late frame is worthless, the next
one is already on its way. Keyframes are sent only on request, so a clean link
spends no bandwidth on them at all.

**Input** needs the opposite guarantee: a lost key-up leaves a modifier stuck, so
input runs over a small sequenced/acked channel with retransmits and a reorder
buffer. It carries a few hundred bytes a second, so this costs nothing.

Printable characters travel as **text**, not keycodes, so the two machines do not
need the same keyboard layout. Modifiers, function keys, and anything pressed
with Ctrl or Alt travel as key events instead, so shortcuts still work.

**Bitrate adapts.** The viewer reports what actually arrived; the host climbs
additively while frames are landing intact and backs off multiplicatively the
moment they are not.

## Viewer shortcuts

Handled locally, never forwarded to the host:

| | |
|---|---|
| `Ctrl+Alt+H` | toggle the stats overlay |
| `Ctrl+Alt+F` | fullscreen |
| `Ctrl+Alt+Q` | disconnect |

## Tests

```bash
python test_selftest.py    # 19 checks: crypto, replay, fragmentation, STUN, codes
python test_endtoend.py    # runs a real host.py and decodes its screen
```

The end-to-end test deliberately never sends mouse or keyboard events — it would
seize the desktop of whoever runs it. It proves the input channel by requesting a
keyframe and watching one come back over that same path.

Individual modules are runnable too:

```bash
python -m common.nat       # classify this network, print a code
python -m common.link      # two encrypted links over loopback
python -m common.video --show   # capture, encode and decode locally
```

## Layout

| | |
|---|---|
| `common/crypto.py` | X25519 handshake, AEAD, replay window, fingerprint words |
| `common/protocol.py` | packet types, fragmentation, reliable channel, input codec |
| `common/nat.py` | STUN, NAT classification, connection codes |
| `common/link.py` | hole punching and the live session |
| `common/video.py` | capture, H.264 encode, H.264 decode |
| `host.py` | the machine being controlled |
| `viewer.py` | the PySide6 application |

## Not built

Audio, file transfer, clipboard sync, and multi-monitor switching are all clean
additions later; none of them change the core. UPnP port mapping would be the
most useful next step — asking your own router to open a port directly removes
even the STUN dependency and rescues some of the networks listed above.
