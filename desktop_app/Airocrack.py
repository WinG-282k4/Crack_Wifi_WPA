#!/usr/bin/env python3
# aircrack_gui_with_guide_clean_output.py
# Variant of previous GUI wrapper with cleaned/parsed aircrack-ng output:
# - Do NOT show the full command in the UI
# - Strip ANSI/control sequences
# - Extract and show concise progress lines (tested/total, % and ETA)
# - Highlight KEY FOUND lines

import sys, shutil, subprocess, os, re
from PyQt5 import QtWidgets, QtCore, QtGui

# --- Worker (same as before) ---
class Worker(QtCore.QThread):
    output_line = QtCore.pyqtSignal(str)
    finished_signal = QtCore.pyqtSignal(int)

    def __init__(self, cmd_list):
        super().__init__()
        self.cmd_list = cmd_list
        self._proc = None
        self._stop_requested = False

    def run(self):
        try:
            self._proc = subprocess.Popen(
                self.cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True,
                text=True
            )
            # Read line-oriented; also handle '\r' heavy output by splitting on \n and emitting cleaned lines
            while True:
                if self._proc.stdout is None:
                    break
                chunk = self._proc.stdout.readline()
                if chunk == "" and self._proc.poll() is not None:
                    break
                if chunk:
                    # emit raw chunk (we will clean in UI thread)
                    self.output_line.emit(chunk.rstrip("\n"))
                if self._stop_requested:
                    try:
                        self._proc.terminate()
                    except Exception:
                        pass
                    break
            rc = self._proc.returncode if self._proc else -1
            self.finished_signal.emit(rc)
        except Exception as e:
            self.output_line.emit(f"[ERROR] {e}")
            self.finished_signal.emit(-1)

    def stop(self):
        self._stop_requested = True
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

# --- Main GUI ---
class AircrackGui(QtWidgets.QWidget):
    ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')  # basic ANSI CSI sequences
    # extra cleans: remove device control strings & other control chars except \t and printable
    CONTROL_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]')

    PROGRESS_RE = re.compile(r'(\d{1,9})/(\d{1,9})\s+keys tested.*(?:Time left:\s*([^\r\n]+))?', re.IGNORECASE)
    KEY_FOUND_RE = re.compile(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', re.IGNORECASE)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Aircrack-ng GUI (clean output)")
        self.resize(900, 560)
        layout = QtWidgets.QVBoxLayout(self)

        # top
        top = QtWidgets.QHBoxLayout()
        self.aircrack_label = QtWidgets.QLabel("")
        top.addWidget(self.aircrack_label)
        top.addStretch()
        self.install_btn = QtWidgets.QPushButton("Check / Install aircrack-ng")
        self.install_btn.clicked.connect(self.check_install)
        top.addWidget(self.install_btn)
        layout.addLayout(top)

        # form
        form = QtWidgets.QFormLayout()
        self.capture_edit = QtWidgets.QLineEdit()
        self.capture_btn = QtWidgets.QPushButton("Choose capture")
        self.capture_btn.clicked.connect(self.select_capture)
        h1 = QtWidgets.QHBoxLayout(); h1.addWidget(self.capture_edit); h1.addWidget(self.capture_btn)
        form.addRow("Capture file:", h1)

        self.wordlist_edit = QtWidgets.QLineEdit()
        self.wordlist_btn = QtWidgets.QPushButton("Choose wordlist")
        self.wordlist_btn.clicked.connect(self.select_wordlist)
        h2 = QtWidgets.QHBoxLayout(); h2.addWidget(self.wordlist_edit); h2.addWidget(self.wordlist_btn)
        form.addRow("Wordlist:", h2)

        self.bssid_edit = QtWidgets.QLineEdit()
        self.bssid_edit.setPlaceholderText("Optional: 00:11:22:33:44:55")
        form.addRow("BSSID (optional):", self.bssid_edit)

        layout.addLayout(form)

        btn_h = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start")
        self.start_btn.clicked.connect(self.start_aircrack)
        btn_h.addWidget(self.start_btn)
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_aircrack)
        btn_h.addWidget(self.stop_btn)
        btn_h.addStretch()
        layout.addLayout(btn_h)

        self.output = QtWidgets.QPlainTextEdit()
        self.output.setReadOnly(True)
        font = QtGui.QFont("Monospace")
        font.setStyleHint(QtGui.QFont.TypeWriter)
        self.output.setFont(font)
        layout.addWidget(self.output)

        self.status = QtWidgets.QLabel("Ready")
        layout.addWidget(self.status)

        self.worker = None
        self.log_lines = []
        self.check_aircrack_presence()

    def check_aircrack_presence(self):
        path = shutil.which("aircrack-ng")
        if path:
            self.aircrack_label.setText(f"aircrack-ng found: {path}")
            self.aircrack_label.setStyleSheet("color: green")
        else:
            self.aircrack_label.setText("aircrack-ng not found")
            self.aircrack_label.setStyleSheet("color: red")

    def check_install(self):
        dlg = QtWidgets.QMessageBox.question(self, "Install", "This will run: sudo apt update && sudo apt install -y aircrack-ng\nContinue?",
                                             QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if dlg == QtWidgets.QMessageBox.Yes:
            cmd = "sudo apt update && sudo apt install -y aircrack-ng"
            try:
                p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                QtWidgets.QMessageBox.information(self, "Output", p.stdout[:10000] or "Done")
                self.check_aircrack_presence()
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "Error", str(e))

    def select_capture(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose capture file", "", "Capture Files (*.pcap *.cap *.pcapng);;All files (*)")
        if path:
            self.capture_edit.setText(path)

    def select_wordlist(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose wordlist", "", "Text Files (*.txt *.lst);;All files (*)")
        if path:
            self.wordlist_edit.setText(path)

    # --- cleaning utilities ---
    def clean_ansi(self, text: str) -> str:
        # remove ANSI CSI sequences and other control chars, also strip carriage returns
        s = text
        s = s.replace("\r", "")            # remove carriage returns that mess formatting
        s = self.ANSI_RE.sub("", s)        # strip color/CSI sequences
        s = self.CONTROL_RE.sub("", s)     # strip other control chars
        return s

    def parse_progress(self, text: str):
        m = self.PROGRESS_RE.search(text)
        if not m:
            return None
        tested = int(m.group(1))
        total = int(m.group(2))
        eta = m.group(3) or ""
        pct = (tested / total) * 100 if total > 0 else 0.0
        return tested, total, pct, eta.strip()

    def parse_key_found(self, text: str):
        m = self.KEY_FOUND_RE.search(text)
        if m:
            return m.group(1).strip()
        return None

    # --- UI append helpers ---
    def append_plain(self, text: str):
        # append plain (no HTML) - keep internal log as plain text
        self.log_lines.append(text)
        self.output.appendPlainText(text)

    def append_highlight(self, text: str):
        # highlight by inserting colored HTML: QPlainTextEdit doesn't support HTML, so use QTextEdit instead if needed.
        # Here we approximate by prefixing with >>> and using plain text (safe and simple).
        self.log_lines.append(text)
        self.output.appendPlainText(">>> " + text)

    # --- starting / stopping ---
    def start_aircrack(self):
        cap = self.capture_edit.text().strip()
        wl = self.wordlist_edit.text().strip()
        if not cap or not os.path.isfile(cap):
            QtWidgets.QMessageBox.warning(self, "Missing capture", "Please choose a valid capture file.")
            return
        if not wl or not os.path.isfile(wl):
            QtWidgets.QMessageBox.warning(self, "Missing wordlist", "Please choose a valid wordlist file.")
            return
        cmd = ["aircrack-ng", "-w", wl, cap]
        bssid = self.bssid_edit.text().strip()
        if bssid:
            cmd.extend(["-b", bssid])

        # IMPORTANT: do NOT show the full command in UI (user asked). Only show a short "Running..." message.
        self.output.clear(); self.log_lines = []
        self.status.setText("Running aircrack-ng...")
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)

        self.worker = Worker(cmd)
        self.worker.output_line.connect(self.on_output_line)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

    def stop_aircrack(self):
        if self.worker:
            self.worker.stop()
            self.append_plain("[Requested stop]")
            self.status.setText("Stopping...")

    # --- handle worker output ---
    def on_output_line(self, raw_line: str):
        # Clean ANSI/control sequences first
        line = self.clean_ansi(raw_line)
        line = line.strip()
        if not line:
            return

        # Parse KEY FOUND first
        key = self.parse_key_found(line)
        if key:
            self.append_highlight(f"KEY FOUND: {key}")
            self.status.setText("KEY FOUND")
            return

        # Parse progress lines like "867/10303727 keys tested ... Time left: ..."
        prog = self.parse_progress(line)
        if prog:
            tested, total, pct, eta = prog
            pct_str = f"{pct:0.2f}%"
            short = f"Progress: {tested}/{total} keys ({pct_str})"
            if eta:
                short += f" — ETA: {eta}"
            self.append_plain(short)
            self.status.setText(short)
            return

        # Otherwise, show a few useful lines: e.g. "Read X packets." or "1 potential targets"
        # We'll show lines that are informative and skip noisy hex dumps, MK/TK blocks, etc.
        if re.search(r'Read\s+\d+\s+packets', line, re.IGNORECASE) or \
           re.search(r'potential targets', line, re.IGNORECASE) or \
           re.search(r'Opening\s+.+', line, re.IGNORECASE) or \
           re.search(r'Resetting EAPOL Handshake decoder', line, re.IGNORECASE) or \
           re.search(r'Time left:', line, re.IGNORECASE) or \
           re.search(r'Current passphrase:', line, re.IGNORECASE):
            self.append_plain(line)
            return

        # Otherwise ignore very verbose lines (master key / transient key / HEAPOL prints)
        # Heuristic: if the line contains many hex bytes separated by spaces, skip it
        if re.match(r'^[0-9A-Fa-f ]{20,}$', line.replace(" ", "")):
            return

        # fallback: append the cleaned line (short)
        self.append_plain(line)

    def on_finished(self, rc):
        self.append_plain(f"[Process exited with code {rc}]")
        self.status.setText("Finished" if rc == 0 else f"Exited ({rc})")
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.worker = None

# --- run ---
def main():
    app = QtWidgets.QApplication(sys.argv)
    win = AircrackGui()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
