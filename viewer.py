"""Viewer: connects to a host, shows its screen, and sends your input back.

Local shortcuts, which are handled here and never forwarded to the host:
  Ctrl+Alt+H   toggle the stats overlay
  Ctrl+Alt+F   toggle fullscreen
  Ctrl+Alt+Q   disconnect
"""
from __future__ import annotations

import sys
import threading
import time

import numpy as np
from PySide6.QtCore import QObject, QRect, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication, QImage, QPainter
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from common import crypto, link, nat, protocol, video

MOUSE_HZ = 60
KEYFRAME_COOLDOWN = 0.5  # asking on every drop is what makes a bad link worse
CLIPBOARD_POLL_MS = 500  # no portable clipboard-change event exists, so poll

_QT_SPECIAL = {
    Qt.Key_Escape: protocol.K_ESC,
    Qt.Key_Tab: protocol.K_TAB,
    Qt.Key_Backtab: protocol.K_TAB,
    Qt.Key_Backspace: protocol.K_BACKSPACE,
    Qt.Key_Return: protocol.K_ENTER,
    Qt.Key_Enter: protocol.K_ENTER,
    Qt.Key_Delete: protocol.K_DELETE,
    Qt.Key_Insert: protocol.K_INSERT,
    Qt.Key_Home: protocol.K_HOME,
    Qt.Key_End: protocol.K_END,
    Qt.Key_PageUp: protocol.K_PAGEUP,
    Qt.Key_PageDown: protocol.K_PAGEDOWN,
    Qt.Key_Up: protocol.K_UP,
    Qt.Key_Down: protocol.K_DOWN,
    Qt.Key_Left: protocol.K_LEFT,
    Qt.Key_Right: protocol.K_RIGHT,
    Qt.Key_Shift: protocol.K_SHIFT,
    Qt.Key_Control: protocol.K_CTRL,
    Qt.Key_Alt: protocol.K_ALT,
    Qt.Key_Meta: protocol.K_META,
    Qt.Key_CapsLock: protocol.K_CAPSLOCK,
    Qt.Key_Print: protocol.K_PRINTSCREEN,
    Qt.Key_Menu: protocol.K_MENU,
    Qt.Key_NumLock: protocol.K_NUMLOCK,
}
for _i in range(24):
    _QT_SPECIAL[Qt.Key(Qt.Key_F1 + _i)] = protocol.K_F1 + _i

_QT_BUTTONS = {Qt.LeftButton: 0, Qt.RightButton: 1, Qt.MiddleButton: 2}


class Backend(QObject):
    """Owns the socket, the link and the decoder; talks to the UI through signals."""

    code_ready = Signal(str, str)  # our connection code, the NAT report
    progress = Signal(str)
    connected = Signal(str, str)  # path description, fingerprint
    failed = Signal(str)
    frame_ready = Signal(object)  # a BGR ndarray
    host_hello = Signal(int, int, bool)
    clipboard_arrived = Signal(str)
    lost = Signal(str)

    def __init__(self, port: int = 0) -> None:
        super().__init__()
        self.link: link.Link | None = None
        # A pinned port survives restarts, so a code stays valid instead of dying
        # the moment you relaunch. 0 picks a random one.
        self.sock = link.new_socket(port)
        self._priv, self._pubkey = crypto.generate_keypair()
        self._decoder = video.Decoder()
        self._keepalive: nat.MappingKeepalive | None = None
        self._seen_keyframe = False
        self._decoded = 0
        self._last_dropped = 0
        self._last_keyframe_request = 0.0
        self.control_allowed = False
        # The last clipboard we either sent or applied; without it, applying the
        # host's clipboard reads as a local change and echoes straight back.
        self._clip_seen: str | None = None
        self._clip_rx = protocol.ClipboardAssembler()

    def gather(self) -> None:
        def work() -> None:
            try:
                code, report = nat.gather(self.sock, self._pubkey)
            except Exception as exc:
                self.failed.emit(f"Could not probe this network: {exc}")
                return
            self._keepalive = nat.MappingKeepalive(self.sock)
            self._keepalive.__enter__()  # hold the NAT mapping open while the user copies
            self.code_ready.emit(code.encode(), report.explain())

        threading.Thread(target=work, daemon=True).start()

    def connect_to(self, peer_text: str) -> None:
        try:
            peer = nat.Code.decode(peer_text)
        except nat.BadCode as exc:
            self.failed.emit(f"That code is not usable: {exc}")
            return

        def work() -> None:
            if self._keepalive:
                self._keepalive.__exit__()  # stop touching the socket before punching
                self._keepalive = None
            try:
                established = link.punch(
                    self.sock, self._priv, peer.pubkey, peer.candidates(),
                    timeout=150.0, on_progress=self.progress.emit,
                )
            except link.PunchFailed as exc:
                self.failed.emit(str(exc))
                return
            self.link = established
            established.start(on_video=self._on_video, on_reliable=self._on_reliable)
            self.connected.emit(
                f"{established.path} -> {established.peer[0]}:{established.peer[1]}",
                established.fingerprint,
            )
            established.send_reliable(protocol.keyframe_request())
            threading.Thread(target=self._report_loop, daemon=True).start()

        threading.Thread(target=work, daemon=True).start()

    def _on_video(self, encoded: bytes, is_keyframe: bool) -> None:
        # ponytail: decoding on the receive thread. ~7ms per frame against a 33ms
        # budget, so there is room. Move to its own thread if decode ever nears
        # the frame interval, or the socket buffer will start overflowing.
        if not self._seen_keyframe:
            if not is_keyframe:
                return  # joining mid-stream: anything before the first IDR is garbage
            self._seen_keyframe = True
        assert self.link
        if self.link.dropped_frames > self._last_dropped:
            self._last_dropped = self.link.dropped_frames
            now = time.perf_counter()
            if now - self._last_keyframe_request > KEYFRAME_COOLDOWN:
                self._last_keyframe_request = now
                self.link.send_reliable(protocol.keyframe_request())
        for frame in self._decoder.decode(encoded):
            self._decoded += 1
            self.frame_ready.emit(frame)

    def _on_reliable(self, payload: bytes) -> None:
        message = protocol.decode_message(payload)
        if message[0] == protocol.M_HELLO:
            self.control_allowed = bool(message[3])
            self.host_hello.emit(message[1], message[2], self.control_allowed)
        elif message[0] == protocol.M_CLIPBOARD and self.control_allowed:
            text = self._clip_rx.push(message[1], message[2])
            if text is not None:
                self._clip_seen = text
                self.clipboard_arrived.emit(text)  # setText must run on the GUI thread

    def apply_clipboard(self, text: str) -> None:
        QGuiApplication.clipboard().setText(text)

    def poll_clipboard(self) -> None:
        """Send our clipboard to the host when it changes. GUI thread, cheap."""
        if not (self.link and self.control_allowed):
            return
        text = QGuiApplication.clipboard().text()
        if not text or text == self._clip_seen:
            return
        self._clip_seen = text
        for chunk in protocol.clipboard_chunks(text):
            self.link.send_reliable(chunk)

    def _report_loop(self) -> None:
        """Tell the host what actually arrived, so it can pick a sane bitrate."""
        while self.link and self.link.alive:
            time.sleep(2.0)
            if self.link:
                self.link.send_reliable(
                    protocol.report(self._decoded, self.link.dropped_frames, int(self.link.rtt * 1000))
                )
        if self.link:
            self.lost.emit("The host stopped responding.")

    def send(self, payload: bytes) -> None:
        if self.link and self.control_allowed:
            self.link.send_reliable(payload)

    def close(self) -> None:
        if self._keepalive:
            self._keepalive.__exit__()
            self._keepalive = None
        if self.link:
            self.link.close()
            self.link = None
        else:
            self.sock.close()


class ConnectPage(QWidget):
    """The two-code exchange, with the NAT verdict shown before anything is tried."""

    def __init__(self, backend: Backend) -> None:
        super().__init__()
        self.backend = backend
        self._pending_peer_code = ""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)

        title = QLabel("Remote Desktop")
        title.setStyleSheet("font-size: 22px; font-weight: 600;")
        layout.addWidget(title)

        self.report = QPlainTextEdit(readOnly=True)
        self.report.setFont(QFont("Consolas", 9))
        self.report.setPlainText("Probing this network...")
        self.report.setFixedHeight(150)
        layout.addWidget(self.report)

        layout.addWidget(QLabel("<b>Step 1.</b> Send this code to the person running the host:"))
        row = QHBoxLayout()
        self.own_code = QLineEdit(readOnly=True)
        self.own_code.setFont(QFont("Consolas", 10))
        self.own_code.setPlaceholderText("waiting for the network probe...")
        self.copy = QPushButton("Copy")
        self.copy.setEnabled(False)
        self.copy.clicked.connect(self._copy)
        row.addWidget(self.own_code, 1)
        row.addWidget(self.copy)
        layout.addLayout(row)

        layout.addWidget(QLabel("<b>Step 2.</b> Paste the code the host printed:"))
        row2 = QHBoxLayout()
        self.peer_code = QLineEdit()
        self.peer_code.setFont(QFont("Consolas", 10))
        self.peer_code.setPlaceholderText("RD1-...")
        self.peer_code.returnPressed.connect(self._connect)
        self.connect_button = QPushButton("Connect")
        self.connect_button.setDefault(True)
        self.connect_button.clicked.connect(self._connect)
        row2.addWidget(self.peer_code, 1)
        row2.addWidget(self.connect_button)
        layout.addLayout(row2)

        self.status = QLabel(" ")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #888;")
        layout.addWidget(self.status)
        layout.addStretch(1)

        backend.code_ready.connect(self._show_code)
        backend.progress.connect(self.status.setText)
        backend.failed.connect(self._show_failure)

    def _copy(self) -> None:
        QGuiApplication.clipboard().setText(self.own_code.text())
        self.status.setText("Copied. Send it however you like -- it is safe to post in a chat.")

    def _show_code(self, code: str, report: str) -> None:
        self.report.setPlainText(report)
        self.own_code.setText(code)
        self.copy.setEnabled(True)
        self.peer_code.setFocus()
        print(f"your code: {code}", flush=True)  # so it can be copied from the terminal too
        if self._pending_peer_code:
            self.peer_code.setText(self._pending_peer_code)
            self._pending_peer_code = ""
            self._connect()

    def prefill(self, peer_code: str) -> None:
        """Connect as soon as our own code exists, without waiting to be typed at."""
        self._pending_peer_code = peer_code

    def _show_failure(self, message: str) -> None:
        self.status.setText(message.replace("\n", "  "))
        self.report.setPlainText(message + "\n\n" + self.report.toPlainText())
        self.connect_button.setEnabled(True)
        self.peer_code.setEnabled(True)

    def _connect(self) -> None:
        text = self.peer_code.text().strip()
        if not text:
            return
        self.connect_button.setEnabled(False)
        self.peer_code.setEnabled(False)
        self.status.setText("Punching...")
        self.backend.connect_to(text)


class VideoCanvas(QWidget):
    """Paints the remote screen letterboxed, and turns local input into messages."""

    disconnect_requested = Signal()
    fullscreen_requested = Signal()

    def __init__(self, backend: Backend) -> None:
        super().__init__()
        self.backend = backend
        self.setFocusPolicy(Qt.StrongFocus)
        self.setMouseTracking(True)
        self.setAutoFillBackground(False)

        self._frame: np.ndarray | None = None
        self._image: QImage | None = None
        self._target = QRect()
        self._show_hud = True
        self._last_mouse = 0.0
        self._frame_times: list[float] = []
        self.path = ""
        self.fingerprint = ""
        self.control_allowed = False

        backend.frame_ready.connect(self._new_frame)

    # -- painting ---------------------------------------------------------

    def _new_frame(self, frame: np.ndarray) -> None:
        self._frame = frame  # QImage does not copy, so this reference must survive
        height, width, _ = frame.shape
        self._image = QImage(frame.data, width, height, frame.strides[0], QImage.Format_BGR888)
        now = time.perf_counter()
        self._frame_times.append(now)
        del self._frame_times[: max(0, len(self._frame_times) - 60)]
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(18, 18, 20))
        if self._image is not None:
            self._target = self._fit(self._image.width(), self._image.height())
            # Smooth scaling costs ~2.4ms a frame and buys nothing at 1:1, which
            # is exactly the case fullscreen on a matching monitor produces.
            scale = self._target.width() / self._image.width()
            if abs(scale - 1.0) > 0.02:
                painter.setRenderHint(QPainter.SmoothPixmapTransform)
            painter.drawImage(self._target, self._image)
        else:
            painter.setPen(QColor(150, 150, 150))
            painter.drawText(self.rect(), Qt.AlignCenter, "waiting for the first keyframe...")
        if self._show_hud:
            self._paint_hud(painter)

    def _fit(self, width: int, height: int) -> QRect:
        """Largest centred rect with the remote aspect ratio -- no stretching."""
        scale = min(self.width() / width, self.height() / height)
        scaled_w, scaled_h = int(width * scale), int(height * scale)
        return QRect((self.width() - scaled_w) // 2, (self.height() - scaled_h) // 2, scaled_w, scaled_h)

    def _paint_hud(self, painter: QPainter) -> None:
        link_ = self.backend.link
        if link_ is None:
            return
        stats = link_.stats
        fps = 0.0
        if len(self._frame_times) > 1:
            fps = (len(self._frame_times) - 1) / (self._frame_times[-1] - self._frame_times[0])
        mbps = link_.bytes_received * 8 / 1e6 / max(1e-6, time.perf_counter() - self._frame_times[0]) if self._frame_times else 0

        lines = [
            f"path      {self.path}",
            f"words     {self.fingerprint}",
            f"fps       {fps:5.1f}",
            f"rtt       {stats['rtt_ms']} ms",
            f"received  {stats['recv_kb']} KB",
            f"dropped   {stats['dropped_frames']} frames",
            f"resends   {stats['retransmits']}",
            f"refused   {stats['rejected']} packets",
            f"input     {'enabled' if self.control_allowed else 'VIEW ONLY'}",
        ]
        painter.setFont(QFont("Consolas", 9))
        metrics = painter.fontMetrics()
        width = max(metrics.horizontalAdvance(line) for line in lines) + 20
        height = metrics.height() * len(lines) + 16
        painter.fillRect(QRect(12, 12, width, height), QColor(0, 0, 0, 170))
        painter.setPen(QColor(220, 220, 220))
        for index, line in enumerate(lines):
            painter.drawText(22, 28 + index * metrics.height(), line)
        painter.setPen(QColor(120, 120, 120))
        painter.drawText(22, 28 + len(lines) * metrics.height(), "Ctrl+Alt+H hud  F fullscreen  Q quit")

    # -- input ------------------------------------------------------------

    def _normalise(self, position) -> tuple[float, float] | None:
        # QRect.contains rejects a QPointF outright, and event.position() is one.
        # Compare in float space: it also keeps the rightmost/bottom pixel column,
        # which rounding to QPoint would throw away.
        if self._target.isEmpty() or not QRectF(self._target).contains(position):
            return None
        return (
            (position.x() - self._target.x()) / self._target.width(),
            (position.y() - self._target.y()) / self._target.height(),
        )

    def mouseMoveEvent(self, event) -> None:
        now = time.perf_counter()
        if now - self._last_mouse < 1.0 / MOUSE_HZ:
            return  # the remote screen cannot use more than this
        self._last_mouse = now
        spot = self._normalise(event.position())
        if spot:
            self.backend.send(protocol.mouse_move(*spot))

    def mousePressEvent(self, event) -> None:
        self.setFocus()
        button = _QT_BUTTONS.get(event.button())
        spot = self._normalise(event.position())
        if button is not None and spot:
            self.backend.send(protocol.mouse_move(*spot))  # click exactly where the cursor is
            self.backend.send(protocol.mouse_button(button, True))

    def mouseReleaseEvent(self, event) -> None:
        button = _QT_BUTTONS.get(event.button())
        if button is not None:
            self.backend.send(protocol.mouse_button(button, False))

    def wheelEvent(self, event) -> None:
        steps = event.angleDelta()
        self.backend.send(protocol.mouse_scroll(steps.x() // 120, steps.y() // 120))

    def _local_shortcut(self, event) -> bool:
        if event.modifiers() & Qt.ControlModifier and event.modifiers() & Qt.AltModifier:
            if event.key() == Qt.Key_H:
                self._show_hud = not self._show_hud
                self.update()
                return True
            if event.key() == Qt.Key_F:
                self.fullscreen_requested.emit()
                return True
            if event.key() == Qt.Key_Q:
                self.disconnect_requested.emit()
                return True
        return False

    def keyPressEvent(self, event) -> None:
        if self._local_shortcut(event):
            return
        special = _QT_SPECIAL.get(event.key())
        if special is not None:
            if not event.isAutoRepeat():  # a held modifier must not restate itself
                self.backend.send(protocol.key(special, True))
            return
        modified = event.modifiers() & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier)
        if event.text() and not modified:
            # Send the character rather than the keycode, so the two machines do
            # not have to share a keyboard layout.
            self.backend.send(protocol.text(event.text()))
        elif event.key() < 128:
            self.backend.send(protocol.key(self._ascii(event.key()), True))

    def keyReleaseEvent(self, event) -> None:
        if event.isAutoRepeat():
            return
        special = _QT_SPECIAL.get(event.key())
        if special is not None:
            self.backend.send(protocol.key(special, False))
        elif event.key() < 128 and event.modifiers() & (
            Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier
        ):
            self.backend.send(protocol.key(self._ascii(event.key()), False))

    @staticmethod
    def _ascii(qt_key: int) -> int:
        """Qt reports letters as uppercase; send lowercase so Shift stays meaningful."""
        return qt_key + 32 if ord("A") <= qt_key <= ord("Z") else qt_key


class ViewerWindow(QMainWindow):
    def __init__(self, port: int = 0) -> None:
        super().__init__()
        self.setWindowTitle("Remote Desktop")
        self.resize(1100, 720)

        self.backend = Backend(port)
        self.pages = QStackedWidget()
        self.connect_page = ConnectPage(self.backend)
        self.canvas = VideoCanvas(self.backend)
        self.pages.addWidget(self.connect_page)
        self.pages.addWidget(self.canvas)
        self.setCentralWidget(self.pages)

        self.backend.connected.connect(self._on_connected)
        self.backend.host_hello.connect(self._on_hello)
        self.backend.clipboard_arrived.connect(self.backend.apply_clipboard)
        self.backend.lost.connect(self._on_lost)
        self.canvas.disconnect_requested.connect(self.close)
        self.canvas.fullscreen_requested.connect(self._toggle_fullscreen)
        self.backend.gather()

        refresh = QTimer(self)  # keeps the HUD numbers moving between frames
        refresh.timeout.connect(self._refresh_hud)
        refresh.start(500)

        self._clipboard_timer = QTimer(self)
        self._clipboard_timer.timeout.connect(self.backend.poll_clipboard)
        self._clipboard_timer.start(CLIPBOARD_POLL_MS)

    def _refresh_hud(self) -> None:
        if self.pages.currentWidget() is self.canvas:
            self.canvas.update()

    def _on_connected(self, path: str, fingerprint: str) -> None:
        self.canvas.path = path
        self.canvas.fingerprint = fingerprint
        self.pages.setCurrentWidget(self.canvas)
        self.canvas.setFocus()
        self.setWindowTitle(f"Remote Desktop  --  {path}  --  {fingerprint}")

    def _on_hello(self, width: int, height: int, control: bool) -> None:
        self.canvas.control_allowed = control
        if not control:
            self.setWindowTitle(self.windowTitle() + "  [view only]")

    def _on_lost(self, message: str) -> None:
        self.setWindowTitle(f"Remote Desktop  --  disconnected: {message}")

    def _toggle_fullscreen(self) -> None:
        self.showNormal() if self.isFullScreen() else self.showFullScreen()

    def closeEvent(self, event) -> None:
        self.backend.close()
        event.accept()


def main() -> None:
    import argparse

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", help="the host's connection code; connects as soon as it can")
    parser.add_argument("--port", type=int, default=0,
                        help="pin the local UDP port so your code survives a restart")
    args, qt_args = parser.parse_known_args()

    app = QApplication(sys.argv[:1] + qt_args)
    app.setStyle("Fusion")
    window = ViewerWindow(args.port)
    if args.code:
        window.connect_page.prefill(args.code)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
