# Remote Desktop

A peer-to-peer remote desktop in Python.

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

Install the dependencies
```bash
python install.py
```

OR By hand: `pip install -r requirements.txt`.

## Running it

```bash
python host.py     # the machine being controlled
python viewer.py   # the machine controlling it
```

# How to connet
Each side prints a connection code. 
- Send the host's to the viewer, paste it in,
- send the viewer's code back to the host, press Enter.
- The HOST will be asked if the Allows this peer to control your mouse and keyboard,
      press ```y``` to accept, and ```n``` to decline.

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
* **Clipboard sync rides the same gate as input** — it only runs once you have
  granted control, so `--view-only` and a refused prompt both disable it, and the
  kill switch cuts it along with everything else. `--no-clipboard` keeps the
  clipboard private while still allowing mouse and keyboard.

## Speed

Measured and rejected, so nobody retries them:

| | |
|---|---|
| threading capture and encode | capture is already just waiting for the next refresh |
| 4:4:4 chroma | real (+5 dB, -27% bytes) but 60 fps -> 46; conversion won't go below 7.5ms vs 2.6 |
| lower resolution at 4:4:4 | 1280 wide scores 23.2 dB, worst of everything tried |
| x264 `superfast`..`faster` | 2-4ms a frame each, none beats `ultrafast` here |
| pinned x264 thread count | 19.8ms against 10.6ms letting it choose |
| `INTER_AREA` downscaling | a third slower than `INTER_LINEAR`, indistinguishable output |
| `8x8dct` on top of `cabac` | +0.01 dB, which is nothing, for real encode time |

## Viewer shortcuts

Handled locally, never forwarded:

| | |
|---|---|
| `Ctrl+Alt+H` | toggle the stats overlay |
| `Ctrl+Alt+F` | fullscreen |
| `Ctrl+Alt+Q` | disconnect |

## Layout

| | |
|---|---|
| `common/crypto.py` | X25519 handshake, AEAD, replay window, fingerprint words |
| `common/protocol.py` | packet types, fragmentation, reliable channel, input codec |
| `common/nat.py` | STUN, NAT classification, connection codes |
| `common/link.py` | hole punching and the live session |
| `common/video.py` | capture, H.264 encode, H.264 decode |
| `common/clipboard.py` | Win32 clipboard for the host; the viewer uses Qt's |
| `host.py` | the machine being controlled |
| `viewer.py` | the PySide6 application |
| `install.py` | installs dependencies, then verifies capture and encoding work |
