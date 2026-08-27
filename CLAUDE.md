# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
python install.py              # install deps, then really grab a frame and open an encoder
python test_selftest.py        # all pure-logic checks, no network, no framework
python test_endtoend.py        # spawns a real host.py and connects to it (needs a punchable network)
python -m common.link          # loopback link demo: punch, video frame, reliable channel
python -m common.nat           # STUN probe + NAT verdict for this machine
python -m common.video         # capture -> encode -> decode with timings (--show to watch)
python -m common.clipboard     # Win32 clipboard round trip
python host.py                 # the machine being controlled
python viewer.py               # the PySide6 controller
```

Run one check from the self-test with `python -c "import test_selftest as t; t.test_name()"`.
There is no pytest, no linter config, no CI. Every module keeps its own
`__main__` demo and those double as the tests for that module — add to the
existing one rather than creating a new file.

## Architecture

Two programs over **one UDP socket each**. That socket is the whole design
constraint: the punched NAT mapping only exists for that socket, so punch
probes, keepalive pings, video fragments and the reliable input channel all
share it, serviced by a single receive thread in `common/link.py`.

Layering, outbound: `protocol` (plaintext framing) -> `crypto.Sealer` (AEAD)
-> socket. Inbound is the reverse, then `Link._dispatch` fans out by packet
type. `protocol` never sees keys; `crypto` never sees packet types.

**Connection flow** (both sides symmetric): `nat.gather()` STUNs to learn the
public `ip:port` and classify the NAT -> prints an `RD1-` code carrying public
addr, LAN addr, X25519 pubkey, CRC -> peer's code is pasted in ->
`link.punch()` races encrypted probes at LAN and WAN candidates -> the first
that decrypts is the peer. `nat.MappingKeepalive` re-STUNs every 15s while a
human copies the code, or the router closes the port first.

**Two channels over the link**: video is fire-and-forget fragments (a late
frame is worthless, so never retransmitted; one lost fragment kills the whole
frame and bumps `Reassembler.lost`), input rides `ReliableChannel` — acked,
in-order, resent on an RTT timer, because a dropped key-up leaves a modifier
stuck down on the host.

**Feedback loop**: viewer counts drops -> asks for a keyframe
(`KEYFRAME_COOLDOWN`, host-side `MIN_KEYFRAME_INTERVAL`) and reports
decoded/dropped every 2s -> host's `BitrateController` does AIMD and calls
`Encoder.set_bitrate`. Both cooldowns exist to stop a bad link from making
itself worse.

## Invariants worth not breaking

- **Consent gates everything.** `video.Capture` is not constructed until the
  host's prompt is answered — nothing is grabbed, even into memory, before
  yes. Clipboard rides the same gate as input (`injector.enabled`), so
  `--view-only`, a refusal, and the kill switch all disable it.
- **`Injector` tracks what it pressed** and `release_all()` runs on kill
  switch, disconnect and exit. Any new input path must keep that true.
- **Anything from the network is untrusted**: `decode_message` returns `(0,)`
  rather than raising, `Opener.open` returns `None`, `ClipboardAssembler` is
  bounded. Keep the no-raise contract on those paths.
- **`Opener._mark` runs only after the tag verifies**, so a forgery cannot
  poison the replay window.
- **Do not downscale**, and **do not strip alpha**. `--max-width 1920` leaves
  1080p untouched on purpose (resampling scores worse on *both* quality and
  bytes), and capture stays BGRA all the way into `cv2.COLOR_BGRA2YUV_I420`.
  The README's "Speed" section lists what was measured and rejected — read it
  before re-trying an optimisation.
- **`Decoder` uses `thread_type = "SLICE"`.** `AUTO` gives frame-threading,
  which silently buffers 8 frames (133ms at 60fps) without moving fps or RTT.
- **`Encoder` reuses one `VideoFrame`**, so `pict_type` is restated on every
  encode — set it back to `NONE` or the stream stays all-IDR. Safe only
  because `zerolatency` means no encoder holds a picture past the call.
- `MAX_DATAGRAM = 1200` already accounts for `crypto.OVERHEAD`; the reliable
  channel does not fragment, so anything larger (clipboard) chunks by hand.
- `common/video.py` `Capture` is thread-affine — one thread only.

## Environment

Windows-first: `dxcam` and `common/clipboard.py` are Win32, both degrade to a
fallback (mss) or a no-op elsewhere. The console is cp1255 — keep printed
output ASCII or it crashes at runtime; both entry points call
`sys.stdout.reconfigure(errors="replace")` for this reason.

Public repo: commits carry no Claude attribution or co-author trailer.
