# Remote Desktop

A peer-to-peer remote desktop in Python. One machine shares its screen as H.264
over UDP; the other decodes it and sends mouse and keyboard back.

No server of any kind — no rendezvous, no relay. The two machines swap a short
code, punch through both NATs, and everything after that flows directly between
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

## Setup

```bash
python install.py
```

Installs the dependencies, then proves the machine can actually run this by
grabbing a real frame and opening a real encoder — importing `mss` says nothing
about permissions, and hardware encoders only fail at open time. Prints which
capture backend and encoder you got.

By hand: `pip install -r requirements.txt`. `dxcam` is Windows-only and
optional; capture falls back to `mss`.

## Running it

```bash
python host.py     # the machine being controlled
python viewer.py   # the machine controlling it
```

Each side prints a connection code. Send the host's to the viewer, paste it in,
send the viewer's code back to the host, press Enter. The codes are safe to post
in a group chat. `python viewer.py --code RD1-...` skips the retyping.

Both ends then show four words. **Check they match** — if they differ, someone
altered a code in transit. Hang up.

## Why the codes are the way they are

68 characters carrying the sender's public `ip:port`, LAN `ip:port`, an X25519
public key, and a checksum.

* **Two addresses**, so two machines on one network connect over the LAN without
  their traffic leaving the building. Candidates are raced; first to answer wins.
* **A public key**, not a password. ECDH gives one ChaCha20-Poly1305 key per
  direction, and the four displayed words fingerprint that secret — which is what
  makes a tampered code visible.
* **A checksum**, so a truncated paste says so instead of timing out mysteriously.

The host must stay running from the moment it prints its code: the public port
exists only while that socket is open. Both sides re-ping STUN every 15s while
waiting, because routers close idle UDP mappings in well under the time it takes
a human to paste a code into a chat window.

## When it will not work

Carrier-grade NAT, most mobile data and some corporate Wi-Fi assign a *different*
public port per destination, making the address in your code meaningless to your
peer. No amount of punching helps.

Both programs detect this first, by asking two STUN servers what port they see
and comparing, so you get told exactly that instead of a blank 90-second timeout.
Move networks, or add a relay if you ever have a server to run one on.

STUN is the only outside contact, and is unavoidable: nothing inside your network
can learn which public port your router picked. It is a 20-byte request revealing
only the public address every website already sees, and it learns nothing about
your peer.

## Safety

This moves a real mouse and presses real keys, so:

* The host **asks before accepting input**, showing the fingerprint words.
  `--view-only` refuses input permanently.
* **Capture does not open until you consent** — nothing is grabbed, even into
  memory, before you say yes.
* **Kill switch: Ctrl+Alt+Shift+K on the host** cuts input instantly and releases
  anything held. The listener sees injected keys too, so either end can trigger it.
* Every datagram is authenticated; counter nonces plus a 64-packet replay window
  mean a captured input packet cannot be replayed later.
* Keys held when a session ends are always released, so a dropped key-up cannot
  leave Ctrl stuck down.

## The protocol

UDP, every datagram sealed with ChaCha20-Poly1305, payloads capped at 1200 bytes
so nothing is IP-fragmented.

**Video** is fragmented with a frame id and fragment index. A frame missing any
fragment is discarded and the viewer asks for a keyframe. Nothing is
retransmitted — a late frame is worthless. Keyframes are sent only on request, so
a clean link spends nothing on them.

**Input** needs the opposite guarantee, since a lost key-up leaves a modifier
stuck: a small sequenced/acked channel with retransmits and a reorder buffer. It
carries a few hundred bytes a second, so this is free.

Printable characters travel as **text**, not keycodes, so the two machines need
not share a keyboard layout. Modifiers and anything with Ctrl or Alt travel as
key events, so shortcuts still work.

**Bitrate adapts** — the host climbs additively while frames land intact and
backs off multiplicatively the moment they do not.

## Speed

The host runs at the capture monitor's refresh rate: the ceiling, not a
coincidence. On 1080p60 with no hardware encoder that is 58-60 fps at full
1920x1080, 11.1ms per frame to convert and encode against a 16.6ms budget.

**Do not downscale.** The old 1600-wide default was the most expensive line in
the program. Against the native desktop at 5 Mbit, 1600 wide scores 26.4 dB at
10.5 KB/frame; native 1920 scores 35.7 dB at 7.3 KB — worse on *both* axes. The
resample softens every glyph and the encoder then spends bits coding the mush.
No bitrate recovers it: 1600 at 20 Mbit reaches only 27.9 dB, losing to native
at a quarter of the bandwidth.

The other big win was one line: `cv2.cvtColor(BGR2YUV_I420)` hands PyAV the
packed layout directly in 2.5ms, where `from_ndarray(bgr24).reformat()` puts
swscale on the critical path at 6.3ms.

Measured and rejected, so nobody retries them:

| | |
|---|---|
| threading capture and encode | capture is already just waiting for the next refresh |
| 4:4:4 chroma | real (+5 dB, -27% bytes) but 60 fps -> 46; conversion won't go below 7.5ms vs 2.6 |
| lower resolution at 4:4:4 | 1280 wide scores 23.2 dB, worst of everything tried |
| x264 `superfast`..`faster` | 2-4ms a frame each, none beats `ultrafast` here |
| pinned x264 thread count | 19.8ms against 10.6ms letting it choose |
| `INTER_AREA` downscaling | a third slower than `INTER_LINEAR`, indistinguishable output |

## Viewer shortcuts

Handled locally, never forwarded:

| | |
|---|---|
| `Ctrl+Alt+H` | toggle the stats overlay |
| `Ctrl+Alt+F` | fullscreen |
| `Ctrl+Alt+Q` | disconnect |

## Tests

```bash
python test_selftest.py    # 20 checks: crypto, replay, fragmentation, STUN, codes, input
python test_endtoend.py    # runs a real host.py and decodes its screen
```

The end-to-end test never sends mouse or keyboard events — that would seize the
desktop of whoever ran it. It proves the input channel by requesting a keyframe
and watching one come back over that path.

Modules are runnable on their own:

```bash
python -m common.nat            # classify this network, print a code
python -m common.link           # two encrypted links over loopback
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
| `install.py` | installs dependencies, then verifies capture and encoding work |

## Not built

Audio, file transfer, clipboard sync and multi-monitor switching are all clean
additions later; none change the core. UPnP port mapping is the most useful next
step — asking your own router to open a port removes even the STUN dependency and
rescues some of the networks above.
