"""Screen capture, H.264 encode, H.264 decode.

Kept in one module because the host needs the first two, the viewer needs the
third, and the round-trip is only meaningfully testable with all three present.

Everything here is tuned for latency rather than file size: no B-frames, no
lookahead, and keyframes emitted on demand instead of on a timer -- a periodic
keyframe wastes bandwidth on a link that has not lost anything.
"""
from __future__ import annotations

import time
from fractions import Fraction

import av
from av.video.frame import PictureType
import cv2
import numpy as np

# Ordered by preference. Hardware encoders cost almost no CPU; libx264 always works.
_ENCODERS: list[tuple[str, dict[str, str]]] = [
    ("h264_nvenc", {"preset": "p1", "tune": "ull", "zerolatency": "1", "delay": "0", "rc": "cbr"}),
    ("h264_qsv", {"preset": "veryfast", "low_power": "1"}),
    ("h264_amf", {"usage": "ultralowlatency", "quality": "speed"}),
    ("libx264", {"preset": "ultrafast", "tune": "zerolatency", "x264-params": "sliced-threads=1"}),
]

# Long GOP: keyframes are requested by the viewer when it actually loses a frame.
GOP = 600


def _even(n: int) -> int:
    return n - (n % 2)  # H.264 chroma subsampling needs even dimensions


class Encoder:
    """Wraps a raw H.264 encoder context; emits Annex-B packets, no container."""

    def __init__(
        self,
        width: int,
        height: int,
        fps: int = 30,
        bitrate: int = 5_000_000,
        codec: str | None = None,
    ) -> None:
        self.width, self.height = _even(width), _even(height)
        self.fps = fps
        self.bitrate = bitrate
        self._pts = 0
        self._force_keyframe = True  # the first frame must be one
        self.name, self._ctx = self._open(codec)

    def _open(self, codec: str | None) -> tuple[str, av.CodecContext]:
        candidates = [(n, o) for n, o in _ENCODERS if codec is None or n == codec]
        if not candidates:
            candidates = [(codec, {})]  # type: ignore[list-item]
        self.rejected: list[str] = []
        probe = np.zeros((self.height, self.width, 3), dtype=np.uint8)
        for name, options in candidates:
            try:
                ctx = self._configure(name, options)
                ctx.encode(self._to_av(probe, 0))  # a codec can only fail at first encode
                self._pts = 1  # pts 0 is spent; reusing it upsets x264
                return name, ctx
            except Exception as exc:  # missing GPU, driver, or ffmpeg build
                self.rejected.append(f"{name}: {type(exc).__name__}: {exc}")
        raise RuntimeError("no usable H.264 encoder\n  " + "\n  ".join(self.rejected))

    def _configure(self, name: str, options: dict[str, str]) -> av.CodecContext:
        ctx = av.CodecContext.create(name, "w")
        ctx.width, ctx.height = self.width, self.height
        ctx.pix_fmt = "yuv420p"
        ctx.bit_rate = self.bitrate
        ctx.framerate = Fraction(self.fps, 1)
        ctx.time_base = Fraction(1, self.fps)
        ctx.gop_size = GOP
        ctx.max_b_frames = 0  # B-frames would add a frame of reorder delay
        ctx.options = options
        return ctx

    def _to_av(self, bgr: np.ndarray, pts: int) -> av.VideoFrame:
        frame = av.VideoFrame.from_ndarray(bgr, format="bgr24").reformat(format="yuv420p")
        frame.pts = pts
        frame.time_base = Fraction(1, self.fps)
        return frame

    def request_keyframe(self) -> None:
        """Ask for an IDR on the next frame; the viewer calls this after packet loss."""
        self._force_keyframe = True

    def set_bitrate(self, bitrate: int) -> None:
        """Retarget the encoder. Rebuilds the context, so only call on real changes."""
        # ponytail: rebuilding is a ~5ms hiccup. Switch to per-frame rate control
        # (ctx.rc_max_rate / nvenc reconfigure) only if that hiccup shows up in practice.
        if abs(bitrate - self.bitrate) < self.bitrate * 0.15:
            return
        self.bitrate = max(200_000, bitrate)
        self.name, self._ctx = self._open(self.name)
        self._force_keyframe = True

    def encode(self, bgr: np.ndarray) -> list[tuple[bytes, bool]]:
        """Encode one BGR frame. Returns (annex-b bytes, is_keyframe) per packet."""
        if bgr.shape[:2] != (self.height, self.width):
            bgr = cv2.resize(bgr, (self.width, self.height), interpolation=cv2.INTER_AREA)
        frame = self._to_av(bgr, self._pts)
        self._pts += 1
        if self._force_keyframe:
            frame.pict_type = PictureType.I
            self._force_keyframe = False
        return [(bytes(p), bool(p.is_keyframe)) for p in self._ctx.encode(frame)]

    def close(self) -> None:
        try:
            self._ctx.encode(None)  # flush
        except Exception:
            pass


class Decoder:
    """Decodes Annex-B H.264 packets back to BGR frames."""

    def __init__(self) -> None:
        self._ctx = av.CodecContext.create("h264", "r")
        self._ctx.thread_type = "AUTO"

    def decode(self, data: bytes) -> list[np.ndarray]:
        try:
            frames = self._ctx.decode(av.packet.Packet(data))
        except Exception:
            return []  # a corrupt access unit; the next keyframe recovers us
        return [f.to_ndarray(format="bgr24") for f in frames]

    def reset(self) -> None:
        """Drop decoder state after a gap, so stale references cannot smear."""
        self._ctx = av.CodecContext.create("h264", "r")
        self._ctx.thread_type = "AUTO"


class Capture:
    """Grabs the screen, preferring DXGI Desktop Duplication where it exists.

    Must be used from a single thread: both backends keep thread-affine handles.
    """

    def __init__(self, monitor: int = 1, max_width: int = 1920) -> None:
        self.max_width = max_width
        self._monitor = monitor
        self._dxcam = None
        self._mss = None
        self._last: np.ndarray | None = None

        # Desktop coordinates of this monitor, needed to place the remote mouse.
        # Read via mss either way: dxcam does not expose the origin.
        import mss as _mss_module

        with getattr(_mss_module, "MSS", _mss_module.mss)() as probe:
            rect = probe.monitors[monitor]
        self.rect = (rect["left"], rect["top"], rect["width"], rect["height"])
        try:
            import dxcam

            self._dxcam = dxcam.create(output_idx=monitor - 1, output_color="BGR")
            if self._dxcam is not None:
                self._dxcam.start(target_fps=0, video_mode=False)
                self.backend = "dxcam (DXGI)"
        except Exception:
            self._dxcam = None
        if self._dxcam is None:
            import mss

            self._mss = getattr(mss, "MSS", mss.mss)()
            self._monitor_rect = self._mss.monitors[monitor]
            self.backend = "mss (BitBlt)"

    @property
    def size(self) -> tuple[int, int]:
        """The (width, height) frames will actually arrive at, after downscaling."""
        frame = self._raw()
        while frame is None:
            time.sleep(0.01)
            frame = self._raw()
        height, width = self._scale(frame).shape[:2]
        return width, height

    def _raw(self) -> np.ndarray | None:
        if self._dxcam is not None:
            return self._dxcam.get_latest_frame()
        shot = self._mss.grab(self._monitor_rect)
        return np.asarray(shot)[:, :, :3]  # BGRA -> BGR

    def _scale(self, frame: np.ndarray) -> np.ndarray:
        height, width = frame.shape[:2]
        if width > self.max_width:
            scale = self.max_width / width
            frame = cv2.resize(
                frame, (_even(int(width * scale)), _even(int(height * scale))),
                interpolation=cv2.INTER_AREA,
            )
        elif width % 2 or height % 2:
            frame = frame[: _even(height), : _even(width)]
        return frame

    def grab(self) -> np.ndarray | None:
        """Return the newest frame, or None if nothing has changed since the last call."""
        frame = self._raw()
        if frame is None:
            return None
        return self._scale(frame)

    def close(self) -> None:
        if self._dxcam is not None:
            self._dxcam.stop()
        if self._mss is not None:
            self._mss.close()


def _demo(show: bool = False, seconds: float = 5.0) -> None:
    """Capture -> encode -> decode on this machine, with timings."""
    capture = Capture()
    width, height = capture.size
    encoder = Encoder(width, height)
    decoder = Decoder()
    print(f"  capture: {capture.backend}  {width}x{height}")
    print(f"  encoder: {encoder.name} @ {encoder.bitrate // 1000} kbps")

    encoded_bytes = grabbed = decoded = 0
    encode_ms: list[float] = []
    decode_ms: list[float] = []
    keyframes = 0
    last_shape = None
    deadline = time.perf_counter() + seconds

    while time.perf_counter() < deadline:
        frame = capture.grab()
        if frame is None:
            continue
        grabbed += 1

        t0 = time.perf_counter()
        packets = encoder.encode(frame)
        encode_ms.append((time.perf_counter() - t0) * 1000)

        for data, is_keyframe in packets:
            encoded_bytes += len(data)
            keyframes += is_keyframe
            t1 = time.perf_counter()
            for out in decoder.decode(data):
                decode_ms.append((time.perf_counter() - t1) * 1000)
                decoded += 1
                last_shape = out.shape
                if show:
                    cv2.imshow("decoded (press q)", out)
                    if cv2.waitKey(1) & 0xFF == ord("q"):
                        deadline = 0
    if show:
        cv2.destroyAllWindows()
    capture.close()
    encoder.close()

    assert grabbed > 0, "capture produced no frames"
    assert decoded > 0, "nothing survived the encode/decode round trip"
    assert last_shape == (encoder.height, encoder.width, 3), (
        f"decoded {last_shape}, expected {(encoder.height, encoder.width, 3)}"
    )
    assert keyframes >= 1, "the stream never contained a keyframe"

    mbps = encoded_bytes * 8 / seconds / 1e6
    mid = lambda xs: sorted(xs)[len(xs) // 2]  # noqa: E731
    print(f"  {grabbed} captured, {decoded} decoded, {keyframes} keyframe(s)")
    print(f"  encode {mid(encode_ms):.1f}ms median, decode {mid(decode_ms):.1f}ms median")
    print(f"  {grabbed / seconds:.0f} fps, {mbps:.2f} Mbps")
    print("\nvideo pipeline ok")


if __name__ == "__main__":
    import sys

    _demo(show="--show" in sys.argv)
