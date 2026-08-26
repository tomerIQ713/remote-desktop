# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

A peer-to-peer remote desktop: `host.py` streams its screen as H.264 over
hole-punched UDP, `viewer.py` (PySide6) decodes it and sends mouse/keyboard
back. `README.md` explains the *why* of every design choice — read it before
arguing with one.

## Commands

```bash
python install.py          # install deps, then prove capture + encoder actually work
python host.py             # share this screen
python viewer.py           # control another machine
python viewer.py --code RD1-...   # skip pasting the host's code

python test_selftest.py    # 19 assert-based checks, no framework
python test_endtoend.py    # spawns a real host.py, punches to it, decodes its screen

python -m common.nat       # classify this network, print a code
python -m common.link      # two encrypted links over loopback
python -m common.video --show   # capture/encode/decode locally
```

There is no lint or format config, and no test framework. `test_selftest.py`
collects every module-level `test_*` and calls it; to run one, edit the
`__main__` filter or `python -c "import test_selftest as t; t.test_replay_is_rejected()"`.

Useful host flags while debugging: `--port` (pin the UDP port so codes survive
restarts), `--yes` (skip the consent prompt), `--view-only`, `--fps`,
`--max-width`, `--bitrate`. `viewer.py` takes `--port` too.

## Architecture

Four layers, each usable without the one above it:

1. **`common/crypto.py`** — X25519 ECDH gives two directional
   ChaCha20-Poly1305 keys plus a 4-word fingerprint of the shared secret.
   `Sealer` prepends a counter nonce; `Opener` enforces a 64-packet replay
   window. Everything on the wire, including punch probes, goes through these.
2. **`common/nat.py`** — STUN query, NAT classification (`NatReport.punchable`),
   and the `RD1-` connection code: version, public `ip:port`, LAN `ip:port`,
   X25519 pubkey, checksum. `Code.candidates()` returns LAN first, then public.
   `MappingKeepalive` re-pings STUN every 15s so the router does not close the
   mapping while a human copies the code.
3. **`common/link.py`** — `punch()` races encrypted probes at every candidate;
   whatever decrypts is provably the peer, and the source address it came from
   becomes `Link.peer`. `Link` then owns the socket: one `link-rx` thread reads,
   decrypts and dispatches by packet type into `on_video` / `on_reliable`
   callbacks.
4. **`common/protocol.py`** — two channels over that one socket.
   *Video* is fragmented (`fragment` / `Reassembler`); a frame missing any
   fragment is dropped and counted, never retransmitted. *Input and control* go
   through `ReliableChannel` (sequenced, acked, retransmitted, reordered),
   because a lost key-up leaves a modifier stuck. `M_*` constants and
   `decode_message` are the input codec — printable characters travel as text
   so keyboard layouts need not match.

`common/video.py` wraps capture (dxcam, falling back to mss) and PyAV
encode/decode. `host.py` composes it all: connect, ask consent, *then* open
capture, run `_capture_loop`, injecting input via pynput. `viewer.py`'s
`Backend` does the same on the other side and hands frames to Qt through
signals — all networking happens on plain threads, never the Qt thread.

Control flow that spans files: viewer counts `link.dropped_frames` → requests a
keyframe (rate-limited) → host's `BitrateController` reads the periodic
`M_REPORT` and climbs additively / backs off multiplicatively.

## Constraints chosen deliberately — do not casually reopen

1. **Hand-rolled NAT traversal, not aiortc/WebRTC.**
2. **Zero servers.** No rendezvous, no relay. STUN is the only external contact
   and is unavoidable: nothing inside a LAN can learn its own public port.

Also non-negotiable, for safety: capture must not open before consent, held keys
must always be released on exit, and the kill switch (Ctrl+Alt+Shift+K) must
keep working even for injected keys.

## Facts that already cost real time

- **Console is cp1255 (Hebrew).** Any non-ASCII in `print()` crashes at
  *runtime*, not import. Keep all CLI output ASCII.
- **`time.monotonic()` quantizes to 15.6ms** on Windows/Py3.12 and zeroed every
  RTT measurement. Everything uses `perf_counter()`.
- **Two "different" STUN servers can resolve to the same IP**
  (`stun.l` / `stun1.l.google.com`), which made the NAT test compare one
  destination with itself and call every network punchable. Servers are
  deduplicated by resolved IP — keep it that way.
- **A keyframe is ~192KB / 166 fragments** against a default 64KB socket buffer.
  Overflow meant the frame never completed, the viewer demanded another
  keyframe, and it spiralled. Fixed by 4MB buffers, burst pacing in
  `send_video`, and a keyframe cooldown at both ends. Do not remove one of the
  three in isolation.
- **Codes go stale on every restart** because a new random port is bound. That
  is the most likely cause of any punch failure; `--port` pins it.
- `cv2.cvtColor(BGR2YUV_I420)` + `from_ndarray(yuv420p)` is 2.5ms where
  `from_ndarray(bgr24).reformat()` is 6.3ms. Pinning x264 thread count made it
  *slower*. Measure before "optimizing" this file.
- **Do not reintroduce a downscale default.** Capturing at 1600 wide instead of
  native 1920 measured 9 dB worse *and* 30% more bytes per frame, and no
  bitrate recovers it. The viewer's `to_ndarray(bgr24)` is likewise already
  faster than the cv2 equivalent (1.5ms vs 3.0ms) -- the host's cv2 win does
  not mirror. 4:4:4 chroma is real (+5 dB, -27% bytes) but costs 60fps -> 46.

## Status

Verified over LAN: 19 self-tests, end-to-end, and an offscreen Qt smoke test all
pass; host runs 58-60fps at native 1920x1080 (the monitor's refresh rate, i.e.
the ceiling). **The cross-internet (WAN) path has never successfully connected** —
that is the open item, and the README still says so. Symmetric NAT (mobile
hotspots, CGNAT) cannot be punched; 21,600 predicted ports proved it. Test on
ordinary Wi-Fi, not a phone.
