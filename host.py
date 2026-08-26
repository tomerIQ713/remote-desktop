"""Host: shares this machine's screen and, with consent, accepts remote input.

Run this on the computer you want to control, then follow the two-code exchange
it prints. Nothing is shared and no input is accepted until you say yes.
"""
from __future__ import annotations

import argparse
import sys
import threading
import time

from pynput import keyboard, mouse

from common import crypto, link, nat, protocol, video

KILL_SWITCH = "<ctrl>+<alt>+<shift>+k"
MIN_KEYFRAME_INTERVAL = 0.5  # seconds; a keyframe costs ~6x a delta frame

_SPECIAL_KEYS = {
    protocol.K_ESC: keyboard.Key.esc,
    protocol.K_TAB: keyboard.Key.tab,
    protocol.K_BACKSPACE: keyboard.Key.backspace,
    protocol.K_ENTER: keyboard.Key.enter,
    protocol.K_DELETE: keyboard.Key.delete,
    protocol.K_INSERT: keyboard.Key.insert,
    protocol.K_HOME: keyboard.Key.home,
    protocol.K_END: keyboard.Key.end,
    protocol.K_PAGEUP: keyboard.Key.page_up,
    protocol.K_PAGEDOWN: keyboard.Key.page_down,
    protocol.K_UP: keyboard.Key.up,
    protocol.K_DOWN: keyboard.Key.down,
    protocol.K_LEFT: keyboard.Key.left,
    protocol.K_RIGHT: keyboard.Key.right,
    protocol.K_SHIFT: keyboard.Key.shift,
    protocol.K_CTRL: keyboard.Key.ctrl,
    protocol.K_ALT: keyboard.Key.alt,
    protocol.K_META: keyboard.Key.cmd,
    protocol.K_CAPSLOCK: keyboard.Key.caps_lock,
}
for _name, _id in [("print_screen", protocol.K_PRINTSCREEN), ("menu", protocol.K_MENU),
                   ("num_lock", protocol.K_NUMLOCK)]:
    if hasattr(keyboard.Key, _name):  # not every platform defines all of these
        _SPECIAL_KEYS[_id] = getattr(keyboard.Key, _name)
for _i in range(24):
    if hasattr(keyboard.Key, f"f{_i + 1}"):
        _SPECIAL_KEYS[protocol.K_F1 + _i] = getattr(keyboard.Key, f"f{_i + 1}")

_BUTTONS = [mouse.Button.left, mouse.Button.right, mouse.Button.middle]


class Injector:
    """Applies remote input to the real desktop, and can always undo itself.

    It tracks what it has pressed so a dropped key-up, a kill switch or a
    disconnect cannot leave a modifier stuck down on the host.
    """

    def __init__(self, rect: tuple[int, int, int, int]) -> None:
        self.rect = rect
        self.enabled = False
        self._mouse = mouse.Controller()
        self._keyboard = keyboard.Controller()
        self._held_keys: set = set()
        self._held_buttons: set = set()

    def apply(self, message: tuple) -> None:
        if not self.enabled:
            return
        kind = message[0]
        try:
            if kind == protocol.M_MOUSE_MOVE:
                left, top, width, height = self.rect
                self._mouse.position = (
                    left + int(message[1] / 65535 * width),
                    top + int(message[2] / 65535 * height),
                )
            elif kind == protocol.M_MOUSE_BUTTON:
                index, pressed = message[1], bool(message[2])
                if index >= len(_BUTTONS):
                    return
                button = _BUTTONS[index]
                if pressed:
                    self._mouse.press(button)
                    self._held_buttons.add(button)
                else:
                    self._mouse.release(button)
                    self._held_buttons.discard(button)
            elif kind == protocol.M_MOUSE_SCROLL:
                self._mouse.scroll(message[1], message[2])
            elif kind == protocol.M_KEY:
                pressed, key_id = bool(message[1]), message[2]
                target = (
                    keyboard.KeyCode.from_char(chr(key_id))
                    if key_id < 128
                    else _SPECIAL_KEYS.get(key_id)
                )
                if target is None:
                    return
                if pressed:
                    self._keyboard.press(target)
                    self._held_keys.add(target)
                else:
                    self._keyboard.release(target)
                    self._held_keys.discard(target)
            elif kind == protocol.M_TEXT:
                self._keyboard.type(message[1])
        except Exception as exc:  # a key the platform refuses should not kill the session
            print(f"  [input] ignored {kind}: {exc}", file=sys.stderr)

    def release_all(self) -> None:
        """Let go of everything we are holding. Safe to call repeatedly."""
        for key in list(self._held_keys):
            try:
                self._keyboard.release(key)
            except Exception:
                pass
        for button in list(self._held_buttons):
            try:
                self._mouse.release(button)
            except Exception:
                pass
        self._held_keys.clear()
        self._held_buttons.clear()

    def disable(self, why: str) -> None:
        self.enabled = False
        self.release_all()
        print(f"\n  !! remote input disabled: {why}")


class BitrateController:
    """Additive-increase, multiplicative-decrease on the viewer's loss reports.

    Climb slowly while the picture is arriving intact, back off hard the moment
    it is not. Same shape as TCP congestion control, without the pretence of
    being one.
    """

    def __init__(self, start: int, ceiling: int, floor: int = 300_000) -> None:
        self.bitrate = start
        self.ceiling = ceiling
        self.floor = floor
        self._seen = (0, 0)

    def update(self, decoded: int, dropped: int) -> int:
        delivered = decoded - self._seen[0]
        lost = dropped - self._seen[1]
        self._seen = (decoded, dropped)
        if delivered + lost < 10:
            return self.bitrate  # too small a sample to react to
        if lost / (delivered + lost) > 0.02:
            self.bitrate = max(self.floor, int(self.bitrate * 0.7))
        else:
            self.bitrate = min(self.ceiling, self.bitrate + 500_000)
        return self.bitrate


class Host:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.link: link.Link | None = None
        # Capture is not opened until consent is given, so nothing is grabbed
        # from the screen -- even into memory -- before you say yes.
        self.capture: video.Capture | None = None
        self.injector: Injector | None = None
        self.encoder: video.Encoder | None = None
        self.rates = BitrateController(args.bitrate, args.bitrate)
        self._keyframe_wanted = threading.Event()
        self._last_keyframe = 0.0
        self._stop = threading.Event()
        self._report = (0, 0, 0)

    # -- connection -------------------------------------------------------

    def connect(self) -> link.Link:
        sock = link.new_socket(self.args.port)
        priv, pubkey = crypto.generate_keypair()

        print("Probing this network...\n")
        code, report = nat.gather(sock, pubkey)
        print(report.explain())
        if not report.punchable:
            print("\n  Continuing anyway -- but expect the punch below to fail.")

        print("\n" + "=" * 72)
        print("  STEP 1  Send this code to whoever is connecting:\n")
        print(f"    {code.encode()}\n")
        print("  STEP 2  Paste the code their viewer prints back, then press Enter.")
        print("=" * 72)

        with nat.MappingKeepalive(sock):  # the router must not close our port while you copy
            peer_code = self._read_peer_code()

        print("\nPunching...")
        try:
            established = link.punch(
                sock, priv, peer_code.pubkey, peer_code.candidates(),
                timeout=self.args.timeout, on_progress=lambda m: print(f"  {m}"),
            )
        except link.PunchFailed as exc:
            print(f"\nCould not connect.\n{exc}\n")
            print("This machine's NAT:")
            print(report.explain())
            raise SystemExit(1) from exc
        return established

    def _read_peer_code(self) -> nat.Code:
        while True:
            try:
                raw = input("\n  peer code> ")
            except (EOFError, KeyboardInterrupt):
                raise SystemExit(1) from None
            try:
                return nat.Code.decode(raw)
            except nat.BadCode as exc:
                print(f"  that code is not usable: {exc}")

    def _ask_consent(self) -> bool:
        assert self.link
        print("\n" + "=" * 72)
        print(f"  Connected via {self.link.path} to {self.link.peer[0]}:{self.link.peer[1]}")
        print(f"  Security words:  {self.link.fingerprint}")
        print("  Check those four words match on the other side. If they differ,")
        print("  someone altered the codes in transit -- answer no.")
        print("=" * 72)
        if self.args.view_only:
            print("  Started with --view-only: screen is shared, input stays disabled.")
            return False
        if self.args.yes:
            print("  Started with --yes: remote control enabled.")
            return True
        try:
            return input("\n  Allow this peer to control your mouse and keyboard? [y/N] ").strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    # -- running ----------------------------------------------------------

    def _on_reliable(self, payload: bytes) -> None:
        message = protocol.decode_message(payload)
        kind = message[0]
        if kind == protocol.M_KEYFRAME:
            self._keyframe_wanted.set()
        elif kind == protocol.M_REPORT:
            self._report = (message[1], message[2], message[3])
        elif self.injector:
            self.injector.apply(message)

    def _capture_loop(self) -> None:
        assert self.link and self.encoder and self.capture and self.injector
        frame_id = 0
        interval = 1.0 / self.args.fps
        next_report = time.perf_counter() + 2.0
        window_frames = 0
        window_started = time.perf_counter()
        window_idle = 0
        encode_ms: list[float] = []

        while not self._stop.is_set() and self.link.alive:
            started = time.perf_counter()
            frame = self.capture.grab()
            if frame is None:
                window_idle += 1  # nothing on screen changed; there is nothing to send
                time.sleep(0.002)
                continue
            if self._keyframe_wanted.is_set():
                self._keyframe_wanted.clear()
                # A peer asking every frame would make us spend the whole link
                # on keyframes, which is how the loss spiral starts.
                if started - self._last_keyframe > MIN_KEYFRAME_INTERVAL:
                    self._last_keyframe = started
                    self.encoder.request_keyframe()
            encode_started = time.perf_counter()
            packets = self.encoder.encode(frame)
            encode_ms.append((time.perf_counter() - encode_started) * 1000)
            for data, is_keyframe in packets:
                frame_id += 1
                window_frames += 1
                self.link.send_video(frame_id, data, is_keyframe)

            if started >= next_report:
                next_report = started + 2.0
                decoded, dropped, rtt_ms = self._report
                self.encoder.set_bitrate(self.rates.update(decoded, dropped))
                elapsed = started - window_started
                sent_fps = window_frames / elapsed if elapsed else 0.0
                median_encode = sorted(encode_ms)[len(encode_ms) // 2] if encode_ms else 0.0
                # sent fps vs the viewer's fps says immediately which end is slow
                print(
                    f"  sending {sent_fps:4.1f} fps | encode {median_encode:5.1f} ms "
                    f"({self.encoder.name}) | {self.encoder.bitrate // 1000:>5} kbps | "
                    f"rtt {rtt_ms}ms | idle grabs {window_idle:>4} | viewer dropped {dropped} | "
                    f"{'CONTROL' if self.injector.enabled else 'view-only'}   ",
                    end="\r",
                )
                window_frames, window_idle, window_started = 0, 0, started
                encode_ms.clear()
            time.sleep(max(0.0, interval - (time.perf_counter() - started)))

    def run(self) -> None:
        self.link = self.connect()
        allowed = self._ask_consent()

        self.capture = video.Capture(monitor=self.args.monitor, max_width=self.args.max_width)
        self.injector = Injector(self.capture.rect)
        self.injector.enabled = allowed

        width, height = self.capture.size
        self.encoder = video.Encoder(width, height, self.args.fps, self.args.bitrate)
        self.link.start(on_reliable=self._on_reliable)
        self.link.send_reliable(protocol.hello(width, height, allowed))

        print(f"\n  Streaming {width}x{height} at up to {self.args.fps} fps via {self.encoder.name}.")
        if allowed:
            print(f"  Kill switch: press {KILL_SWITCH.replace('<', '').replace('>', '')} to cut input instantly.")
        print("  Ctrl-C to stop.\n")

        hotkey = None
        if allowed:
            hotkey = keyboard.GlobalHotKeys(
                {KILL_SWITCH: lambda: self.injector.disable("kill switch pressed")}
            )
            hotkey.start()
        try:
            self._capture_loop()
            if not self.link.alive:
                print("\n\n  Peer stopped responding.")
        except KeyboardInterrupt:
            print("\n\n  Stopping.")
        finally:
            self._stop.set()
            if self.injector:
                self.injector.release_all()  # never leave a key held on the way out
            if hotkey:
                hotkey.stop()
            if self.encoder:
                self.encoder.close()
            if self.capture:
                self.capture.close()
            self.link.close()
            print(f"  Final: {self.link.stats}")


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor", type=int, default=1, help="which monitor to share (1 = primary)")
    parser.add_argument("--max-width", type=int, default=1600, help="downscale wider screens to this")
    parser.add_argument("--fps", type=int, default=30)
    parser.add_argument("--bitrate", type=int, default=5_000_000, help="ceiling in bits per second")
    parser.add_argument("--port", type=int, default=0, help="local UDP port (0 picks one)")
    parser.add_argument("--timeout", type=float, default=90.0, help="seconds to spend punching")
    parser.add_argument("--view-only", action="store_true", help="share the screen, refuse all input")
    parser.add_argument("--yes", action="store_true", help="skip the consent prompt")
    Host(parser.parse_args()).run()


if __name__ == "__main__":
    main()
