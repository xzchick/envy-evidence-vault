"""A native ENVY Evidence Vault window: a real desktop app, not a web view.

Built with PyQt6 and styled in the ENVY palette with a live animated header.
Create or open an encrypted vault, intake files (copied in, encrypted at rest,
fingerprinted by SHA-256), verify that every stored file is unchanged since
intake, and keep an append-only custody journal. Export a plaintext report.

Nothing is sent: no messages, no network. A hash proves integrity since intake,
not origin or authenticity.
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

from . import __version__
from . import core
from .core import EvidenceError

BG = "#050713"
PANEL = "#0a0e22"
PANEL_HI = "#121735"
INK = "#f2f4ff"
MUTED = "#b9c3df"
DIM = "#6f7898"
PINK = "#ff3db4"
CYAN = "#35e8ff"
LAVENDER = "#ac8cff"
VIOLET = "#8547e8"
AMBER = "#ffb347"
GREEN = "#49e3a6"
LINE = "#1f2547"

KIND_ACCENT = {"intake": CYAN, "verification": GREEN, "transfer": LAVENDER, "note": PINK}
STATUS_COLOR = {"verified": GREEN, "mismatch": PINK, "missing": AMBER, "not verified": DIM, "": DIM}


def lerp(a, b, t):
    from PyQt6.QtGui import QColor
    ca, cb = QColor(a), QColor(b)
    return QColor(int(ca.red() + (cb.red() - ca.red()) * t),
                  int(ca.green() + (cb.green() - ca.green()) * t),
                  int(ca.blue() + (cb.blue() - ca.blue()) * t))


def _build():
    from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF
    from PyQt6.QtGui import (QColor, QPainter, QLinearGradient, QRadialGradient, QFont,
                             QPen, QBrush)
    from PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QPushButton, QPlainTextEdit,
                                 QLineEdit, QTabWidget, QTableWidget, QTableWidgetItem,
                                 QHeaderView, QAbstractItemView, QVBoxLayout, QHBoxLayout,
                                 QFormLayout, QInputDialog, QFileDialog, QMessageBox,
                                 QLineEdit as QLE)

    class Header(QWidget):
        def __init__(self):
            super().__init__()
            self.setFixedHeight(172)
            self.phase = 0.0
            self.stars = [(((i * 139 + 37) % 1000) / 1000.0,
                           ((i * 83 + 19) % 172) / 172.0,
                           0.6 + (i % 3) * 0.5, (i % 7) / 7.0) for i in range(60)]

        def tick(self, phase):
            self.phase = phase
            self.update()

        def paintEvent(self, _event):
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            w, h = self.width(), self.height()
            p.fillRect(self.rect(), QColor(BG))
            for cx, cy, rad, col, a in ((w - 120, 60, 250, CYAN, 60),
                                        (60, h, 280, VIOLET, 52), (w * 0.5, -40, 240, GREEN, 36)):
                g = QRadialGradient(cx, cy, rad)
                c = QColor(col); c.setAlpha(a); g.setColorAt(0, c)
                c2 = QColor(col); c2.setAlpha(0); g.setColorAt(1, c2)
                p.setBrush(QBrush(g)); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(cx, cy), rad, rad)
            for sx, sy, sr, ph in self.stars:
                tw = 0.5 + 0.5 * math.sin(self.phase / 0.5 + ph * 6.28)
                c = QColor(205, 217, 255); c.setAlphaF(0.15 + 0.6 * tw)
                p.setBrush(c); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(sx * w, sy * h), sr, sr)
            pulse = 0.5 + 0.5 * math.sin(self.phase)
            p.setFont(QFont("Helvetica", 22))
            p.setPen(QColor(CYAN) if pulse > 0.5 else QColor(PINK))
            p.drawText(QRectF(22, 28, 44, 44), Qt.AlignmentFlag.AlignCenter, "▧")
            p.setFont(QFont("Helvetica", 33, QFont.Weight.Bold))
            grad = QLinearGradient(70, 0, 640, 0)
            grad.setColorAt(0, QColor(CYAN))
            grad.setColorAt(0.5, QColor(lerp(CYAN, "#ffffff", 0.2 * pulse)))
            grad.setColorAt(1, QColor(PINK))
            glow = QColor(VIOLET); glow.setAlpha(int(55 + 55 * pulse))
            p.setPen(QPen(glow, 1))
            for dx, dy in ((1.3, 1.3), (-1.3, 1.3), (1.3, -1.3)):
                p.drawText(QRectF(70 + dx, 36 + dy, 760, 50), Qt.AlignmentFlag.AlignVCenter, "ENVY EVIDENCE VAULT")
            p.setPen(QPen(QBrush(grad), 1))
            p.drawText(QRectF(70, 36, 760, 50), Qt.AlignmentFlag.AlignVCenter, "ENVY EVIDENCE VAULT")
            p.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
            p.setPen(QColor(LAVENDER))
            p.drawText(QRectF(74, 90, 700, 20), Qt.AlignmentFlag.AlignVCenter,
                       "ENCRYPTED  ·  LOCAL  ·  HASH-VERIFIED")
            y = 126
            p.setPen(QPen(QColor(LINE), 2)); p.drawLine(74, y, w - 54, y)
            p.setPen(QPen(QColor(VIOLET), 3)); p.drawLine(74, y, 146, y)
            span = (w - 54) - 74
            x = 74 + span * ((self.phase * 0.12) % 1.0)
            halo = QRadialGradient(x, y, 15)
            hc = QColor(CYAN); hc.setAlpha(170); halo.setColorAt(0, hc)
            hc2 = QColor(CYAN); hc2.setAlpha(0); halo.setColorAt(1, hc2)
            p.setBrush(QBrush(halo)); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y), 15, 15)
            p.setBrush(QColor("#ffffff")); p.drawEllipse(QPointF(x, y), 2.5, 2.5)
            p.end()

    def make_table(headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setDefaultSectionSize(30)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        return table

    class Window(QWidget):
        def __init__(self):
            super().__init__()
            self.vault = None      # Path of the vault directory
            self.secret = None     # passphrase bytes, kept in memory for this vault only
            self.data = None       # decrypted, validated manifest dict
            self.setWindowTitle("ENVY Evidence Vault")
            self.resize(1200, 900)
            self.setMinimumSize(980, 760)
            self.setStyleSheet(STYLE)
            root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
            self.header = Header(); root.addWidget(self.header)

            body = QWidget(); body.setObjectName("body")
            bl = QVBoxLayout(body); bl.setContentsMargins(22, 14, 22, 16); bl.setSpacing(10)

            intro = QLabel("Intake files into an encrypted vault and verify their integrity locally. Each "
                           "file is copied in, encrypted at rest and fingerprinted; the custody journal is "
                           "append-only. Nothing is sent.")
            intro.setObjectName("status"); intro.setWordWrap(True); bl.addWidget(intro)

            controls = QHBoxLayout()
            for caption, handler, name in (("New vault", self.new_vault, "go"),
                                           ("Open vault", self.open_vault, "pick"),
                                           ("Lock", self.lock, "pick"),
                                           ("Intake file", self.intake_file, "go"),
                                           ("Verify all", self.verify_all, "pick"),
                                           ("Export report", self.export_report, "pick")):
                b = QPushButton(caption); b.setObjectName(name)
                b.setCursor(Qt.CursorShape.PointingHandCursor); b.clicked.connect(handler)
                controls.addWidget(b)
            controls.addStretch(1)
            bl.addLayout(controls)

            self.vault_header = QPlainTextEdit(); self.vault_header.setObjectName("mono")
            self.vault_header.setReadOnly(True); self.vault_header.setFixedHeight(84)
            self.vault_header.setPlainText("No vault open. Create a new encrypted vault or open an existing one.")
            bl.addWidget(self.vault_header)

            self.views = QTabWidget(); self.views.setObjectName("tabs")
            self.t_evidence = make_table(["File", "SHA-256 (original bytes)", "Size", "Custodian",
                                          "Intake UTC", "Last verified"])
            self.t_log = make_table(["UTC", "Event", "Title", "Custodian", "Detail"])
            self.views.addTab(self.t_evidence, "Evidence")
            self.views.addTab(self.t_log, "Custody log")
            bl.addWidget(self.views, 3)

            self.forms = QTabWidget(); self.forms.setObjectName("tabs")
            self.forms.addTab(self._note_form(), "Add note")
            self.forms.addTab(self._transfer_form(), "Record transfer")
            bl.addWidget(self.forms, 1)

            self.path_label = QLabel(""); self.path_label.setObjectName("foot")
            self.path_label.setWordWrap(True); bl.addWidget(self.path_label)
            foot = QLabel("A matching hash proves a file is unchanged since intake — not its origin, author "
                          "or authenticity. Custodian labels and timestamps are operator assertions, not "
                          "identities or trusted facts. Open vaults stay in process memory until lock or close.")
            foot.setObjectName("foot"); foot.setWordWrap(True); bl.addWidget(foot)
            root.addWidget(body, 1)

            self.phase = 0.0
            self.timer = QTimer(self); self.timer.timeout.connect(self._animate); self.timer.start(33)
            self._set_enabled(False)

        # ----- forms --------------------------------------------------------
        def _field(self):
            w = QLineEdit(); w.setObjectName("field"); return w

        def _submit_row(self, caption, handler):
            row = QHBoxLayout()
            btn = QPushButton(caption); btn.setObjectName("go")
            btn.setCursor(Qt.CursorShape.PointingHandCursor); btn.clicked.connect(handler)
            status = QLabel(""); status.setObjectName("status")
            row.addWidget(btn); row.addWidget(status, 1)
            return row, status

        def _note_form(self):
            tab = QWidget(); form = QFormLayout(tab); form.setSpacing(8)
            self.n_title = self._field(); self.n_body = self._field(); self.n_custodian = self._field()
            form.addRow(self._tag("Title"), self.n_title)
            form.addRow(self._tag("Body (optional)"), self.n_body)
            form.addRow(self._tag("Custodian (optional)"), self.n_custodian)
            row, self.n_status = self._submit_row("Record note in a new revision", self.add_note)
            form.addRow(row)
            return tab

        def _transfer_form(self):
            tab = QWidget(); form = QFormLayout(tab); form.setSpacing(8)
            self.x_custodian = self._field(); self.x_note = self._field()
            self.x_custodian.setPlaceholderText("a label, not a verified identity")
            form.addRow(self._tag("New custodian"), self.x_custodian)
            form.addRow(self._tag("Note (optional)"), self.x_note)
            row, self.x_status = self._submit_row("Record transfer in a new revision", self.add_transfer)
            form.addRow(row)
            return tab

        def _tag(self, text):
            lab = QLabel(text); lab.setObjectName("tag"); return lab

        # ----- vault lifecycle ---------------------------------------------
        def _ask_passphrase(self, confirm, prompt="Vault passphrase (at least 12 characters):",
                            title="Passphrase"):
            text, ok = QInputDialog.getText(self, title, prompt, QLE.EchoMode.Password)
            if not ok:
                return None
            secret = text.encode("utf-8")
            if confirm:
                again, ok2 = QInputDialog.getText(self, "Confirm passphrase",
                                                  "Repeat the passphrase:", QLE.EchoMode.Password)
                if not ok2:
                    return None
                if again.encode("utf-8") != secret:
                    self._warn("Passphrases do not match."); return None
            try:
                return core.check_passphrase(secret)
            except EvidenceError as exc:
                self._warn(str(exc)); return None

        def new_vault(self):
            title, ok = QInputDialog.getText(self, "New vault", "Vault / case title:")
            if not ok or not title.strip():
                return
            path, _ = QFileDialog.getSaveFileName(self, "Create a new vault directory", "evidence-vault",
                                                  "Vault directory (*)")
            if not path:
                return
            secret = self._ask_passphrase(confirm=True)
            if secret is None:
                return
            try:
                core.create(path, title.strip(), secret)
                self._open_path(Path(path), secret)
            except (EvidenceError, OSError) as exc:
                self._warn(str(exc))

        def open_vault(self):
            path = QFileDialog.getExistingDirectory(self, "Open an existing vault directory")
            if not path:
                return
            secret = self._ask_passphrase(confirm=False)
            if secret is None:
                return
            self._open_path(Path(path), secret)

        def _open_path(self, path, secret):
            try:
                data, _ = core._load(path, secret)
            except EvidenceError as exc:
                self._warn(str(exc)); return
            self.vault, self.secret, self.data = path, secret, data
            self._set_enabled(True)
            self.refresh_views()

        def lock(self):
            self.vault = self.secret = self.data = None
            for table in (self.t_evidence, self.t_log):
                table.setRowCount(0)
            self.vault_header.setPlainText("Locked. The passphrase was cleared from memory.")
            self.path_label.setText("")
            self._set_enabled(False)

        # ----- intake & verify ---------------------------------------------
        def intake_file(self):
            if not self.data:
                return
            source, _ = QFileDialog.getOpenFileName(self, "Choose a file to intake")
            if not source:
                return
            custodian, ok = QInputDialog.getText(self, "Intake", "Custodian label (optional):")
            if not ok:
                return
            note_text, ok2 = QInputDialog.getText(self, "Intake", "Note (optional):")
            if not ok2:
                return
            try:
                result = core.intake(self.vault, source, self.secret, custodian.strip(), note_text.strip())
            except (EvidenceError, OSError) as exc:
                self._warn(str(exc)); return
            self.data, _ = core._load(self.vault, self.secret)
            self.refresh_views()
            dup = "\n\nThis file was already in the vault; the existing object was referenced." if result["duplicate_object"] else ""
            self._warn(f"Intook {Path(source).name} ({result['size']} bytes).\n\n"
                       f"SHA-256: {result['object_sha256']}{dup}",
                       icon=QMessageBox.Icon.Information, title="File intaken")

        def verify_all(self):
            if not self.data:
                return
            try:
                result = core.verify(self.vault, self.secret, record_result=True)
            except (EvidenceError, OSError) as exc:
                self._warn(str(exc)); return
            self.data, _ = core._load(self.vault, self.secret)
            self.refresh_views()
            icon = QMessageBox.Icon.Information if result["mismatch"] == 0 and result["missing"] == 0 \
                else QMessageBox.Icon.Warning
            self._warn(f"Checked {result['checked']} object(s):\n\n"
                       f"  verified  {result['verified']}\n  mismatch  {result['mismatch']}\n"
                       f"  missing   {result['missing']}\n\n"
                       "A match proves the bytes are unchanged since intake — not their origin or authenticity.",
                       icon=icon, title="Verification complete")

        def export_report(self):
            if not self.data:
                return
            choice, ok = QInputDialog.getItem(self, "Export report", "Format:",
                                              ["HTML report", "JSON report"], 0, False)
            if not ok:
                return
            fmt = "html" if choice.startswith("HTML") else "json"
            dest, _ = QFileDialog.getSaveFileName(self, "Export plaintext report",
                                                  f"evidence-report.{fmt}", f"{fmt.upper()} (*.{fmt});;All files (*)")
            if not dest:
                return
            try:
                if Path(dest).exists():
                    Path(dest).unlink()
                result = core.export(self.vault, dest, self.secret, fmt)
            except (EvidenceError, OSError) as exc:
                self._warn(str(exc)); return
            self._warn(f"Exported a plaintext {fmt.upper()} report to {result['output']}.\n\n"
                       f"SHA-256: {result['sha256']}\n\nThis file is not encrypted — store it per your policy.",
                       icon=QMessageBox.Icon.Information, title="Report exported")

        # ----- custody appends ---------------------------------------------
        def add_note(self):
            if not self.data or not self.n_title.text().strip():
                self.n_status.setText("A note needs a title."); return
            try:
                core.note(self.vault, self.secret, self.n_title.text().strip(),
                          self.n_body.text().strip(), self.n_custodian.text().strip())
            except (EvidenceError, OSError) as exc:
                self.n_status.setText(str(exc)); self.n_status.setStyleSheet(f"#status{{color:{PINK};}}"); return
            self.data, _ = core._load(self.vault, self.secret)
            self.refresh_views()
            self.n_title.clear(); self.n_body.clear(); self.n_custodian.clear()
            self.n_status.setText(f"Saved revision {self.data['revision']}")
            self.n_status.setStyleSheet(f"#status{{color:{CYAN};}}")

        def add_transfer(self):
            if not self.data or not self.x_custodian.text().strip():
                self.x_status.setText("A transfer needs a custodian."); return
            try:
                core.transfer(self.vault, self.secret, self.x_custodian.text().strip(), self.x_note.text().strip())
            except (EvidenceError, OSError) as exc:
                self.x_status.setText(str(exc)); self.x_status.setStyleSheet(f"#status{{color:{PINK};}}"); return
            self.data, _ = core._load(self.vault, self.secret)
            self.refresh_views()
            self.x_custodian.clear(); self.x_note.clear()
            self.x_status.setText(f"Saved revision {self.data['revision']}")
            self.x_status.setStyleSheet(f"#status{{color:{CYAN};}}")

        # ----- display ------------------------------------------------------
        def refresh_views(self):
            if not self.data:
                return
            d = self.data
            ev = core.evidence(d)
            total = sum(e["size"] for e in ev)
            self.vault_header.setPlainText(
                f"{d['title']}  ·  revision {d['revision']}  ·  {len(ev)} object(s)  ·  {total:,} bytes\n"
                f"Vault: {d['vault_id']}")
            self._fill_evidence(ev)
            self._fill_log(core.custody_log(d))
            if self.vault:
                self.path_label.setText(str(self.vault))

        def _cell(self, text, color=None):
            item = QTableWidgetItem("" if text is None else str(text))
            if color:
                item.setForeground(QColor(color))
            return item

        def _fill_evidence(self, rows):
            t = self.t_evidence; t.setRowCount(len(rows))
            for i, r in enumerate(rows):
                verified = r["last_verified_utc"]
                t.setItem(i, 0, self._cell(r["filename"], CYAN))
                t.setItem(i, 1, self._cell(r["object_sha256"]))
                t.setItem(i, 2, self._cell(r["size"]))
                t.setItem(i, 3, self._cell(r["custodian"]))
                t.setItem(i, 4, self._cell(r["intake_utc"]))
                t.setItem(i, 5, self._cell(verified or "not verified", GREEN if verified else DIM))
            t.resizeColumnsToContents(); t.horizontalHeader().setStretchLastSection(True)

        def _fill_log(self, rows):
            t = self.t_log; t.setRowCount(len(rows))
            for i, r in enumerate(reversed(rows)):  # newest first
                detail = ""
                if r["result"]:
                    res = r["result"]
                    detail = f"verified {res['verified']}, mismatch {res['mismatch']}, missing {res['missing']}"
                elif r["kind"] == "intake":
                    detail = f"{r['filename']}  ·  {r['object_sha256'][:16]}…"
                else:
                    detail = r["note"]
                t.setItem(i, 0, self._cell(r["recorded_utc"]))
                t.setItem(i, 1, self._cell(r["kind"], KIND_ACCENT.get(r["kind"], INK)))
                t.setItem(i, 2, self._cell(r["title"]))
                t.setItem(i, 3, self._cell(r["custodian"]))
                t.setItem(i, 4, self._cell(detail))
            t.resizeColumnsToContents(); t.horizontalHeader().setStretchLastSection(True)

        def _set_enabled(self, on):
            for w in (self.views, self.forms):
                w.setEnabled(on)

        def _warn(self, message, icon=None, title="Evidence Vault"):
            box = QMessageBox(self); box.setWindowTitle(title)
            box.setIcon(icon or QMessageBox.Icon.Warning); box.setText(message); box.exec()

        def _animate(self):
            self.phase += 0.05
            self.header.tick(self.phase)

    return QApplication, Window


STYLE = f"""
#body {{ background: {BG}; }}
QWidget {{ color: {INK}; font-family: Helvetica, Arial, sans-serif; font-size: 13px; }}
#tag {{ color: {MUTED}; font-weight: bold; font-size: 11px; letter-spacing: 1px; }}
#status {{ color: {MUTED}; font-size: 12px; }}
#foot {{ color: {DIM}; font-size: 11px; }}
#mono {{ background: {PANEL_HI}; border: 1px solid {LINE}; border-radius: 9px; color: {INK};
         font-family: "Courier New", monospace; font-size: 13px; padding: 8px; }}
#field {{ background: {PANEL_HI}; border: 1px solid {LINE}; border-radius: 8px; color: {INK}; padding: 7px 9px; }}
#field:focus {{ border: 1px solid {CYAN}; }}
QTableWidget {{ background: {PANEL_HI}; alternate-background-color: {PANEL}; border: 1px solid {LINE};
                border-radius: 10px; gridline-color: {LINE}; }}
QTableWidget::item {{ padding: 4px 6px; }}
QTableWidget::item:selected {{ background: {VIOLET}; color: {INK}; }}
QHeaderView::section {{ background: {PANEL}; color: {MUTED}; padding: 6px 8px; border: none;
                        border-bottom: 1px solid {LINE}; font-weight: bold; }}
QTableCornerButton::section {{ background: {PANEL}; border: none; }}
QTabWidget#tabs::pane {{ border: 1px solid {LINE}; border-radius: 12px; background: {PANEL}; }}
QTabBar::tab {{ background: {PANEL_HI}; color: {MUTED}; padding: 8px 18px; margin-right: 6px;
                border-top-left-radius: 9px; border-top-right-radius: 9px; font-weight: bold; }}
QTabBar::tab:selected {{ color: {INK}; border-bottom: 2px solid {PINK}; }}
QPushButton#go {{ background: {PINK}; color: {BG}; border: none; border-radius: 10px; font-weight: bold; padding: 9px 16px; }}
QPushButton#go:hover {{ background: {CYAN}; }}
QPushButton#pick {{ background: {PANEL_HI}; border: 1px solid {LAVENDER}; border-radius: 9px; color: {INK};
                    font-weight: bold; padding: 9px 14px; }}
QPushButton#pick:hover {{ background: #1b2150; }}
"""


def run_app() -> int:
    try:
        from PyQt6.QtWidgets import QApplication  # noqa: F401
    except Exception:
        print("PyQt6 is required for the Evidence Vault window. Use 'envy-evidence-vault' subcommands instead.")
        return 2
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        print("No display found. Use 'envy-evidence-vault new/intake/verify/export' in a terminal instead.")
        return 2
    try:
        QApplication, Window = _build()
        app = QApplication.instance() or QApplication(sys.argv)
        window = Window(); window.show()
        return app.exec()
    except Exception as exc:  # pragma: no cover
        print(f"Could not open the window: {exc}")
        return 2
