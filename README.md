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

## Setup

On each machine, from inside the repo:

```bash
python install.py
```

That installs the dependencies and then checks the machine can actually run
this — it grabs a real frame and opens a real encoder, because importing `mss`
proves nothing about permissions and hardware encoders only fail at open time.
It finishes by telling you which capture backend and which H.264 encoder you
ended up with, and running the self-test.

If you would rather do it by hand, `pip install -r requirements.txt` is the
whole install. `dxcam` is Windows-only and optional; without it capture falls
back to `mss`.

## Running it

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

## Speed

The host runs at the refresh rate of the monitor it is capturing -- the
ceiling, not a coincidence. On a 1080p60 screen with no hardware encoder that
is 58-60 fps at full 1920x1080, spending 11.1ms per frame to convert and
encode, with the rest of the 16.6ms budget waiting for the next refresh.

The default used to downscale to 1600 wide, which turned out to be the most
expensive line in the program. Measured against the native desktop, at the
same 5 Mbit: 1600 wide scores 26.4 dB and costs 10.5 KB a frame, while native
1920 scores 35.7 dB and costs 7.3 KB. Downscaling was *worse on both axes* --
the resample softens every glyph, the encoder then spends bits coding the
mush, and no bitrate recovers it (1600 wide at 20 Mbit still only reaches 27.9
dB, losing to native at a quarter of the bandwidth). Capture native, scale
once at the viewer if at all.

Getting there was mostly one line. The obvious way to feed a BGR frame to PyAV
is `from_ndarray(bgr24).reformat(yuv420p)`, and swscale takes 6.3ms over it.
`cv2.cvtColor(BGR2YUV_I420)` produces the packed layout PyAV accepts directly,
in 2.5ms and with slightly *better* colour accuracy. Two smaller wins came from
measuring rather than assuming: pinning x264 to a thread count made it slower
(19.8ms against 10.6ms letting it choose), as did `sliced-threads=1`, and
`INTER_AREA` downscaling costs a third more than `INTER_LINEAR` for output
nobody can tell apart at these sizes.

Deliberately not done: running capture and encode on separate threads. It looks
like the obvious next move and the arithmetic says it lifts the ceiling to
88fps, but capture is already just waiting for the monitor's next frame, so
overlapping it with encoding wins nothing real.

Also measured and rejected: 4:4:4 chroma, which is the textbook fix for text
on a desktop and does deliver -- +5 dB and 27% fewer bytes than 4:2:0. It
costs 60 fps -> 46, because the planar conversion cannot be done in under
7.5ms against 2.6ms for I420. Resolution beats chroma by a wide margin here:
1280 wide at 4:4:4 scores 23.2 dB, worse than anything else tried. Slower x264
presets were rejected too -- `superfast` through `faster` all cost 2-4ms a
frame and none beat `ultrafast` on quality at these bitrates.

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
| `install.py` | installs dependencies, then verifies capture and encoding work |

## Not built

Audio, file transfer, clipboard sync, and multi-monitor switching are all clean
additions later; none of them change the core. UPnP port mapping would be the
most useful next step — asking your own router to open a port directly removes
even the STUN dependency and rescues some of the networks listed above.
