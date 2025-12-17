#!/usr/bin/env python3
# aircrack_gui_with_hashcat_and_elapsed_auto22000.py
# Hashcat GUI (aircrack -> hccap/hccapx -> auto-convert to .22000 when possible)
# - Supports aircrack-ng conversion saved to cwd
# - Auto-converts captures to .22000 (preferred) if hcxpcapngtool available
# - Auto-selects hash mode (prefers 22000)
# - Shows elapsed time and cleaned output

import sys, shutil, subprocess, os, re, tempfile, time
from PyQt5 import QtWidgets, QtCore, QtGui

# --- Worker (runs external commands) ---
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
            while True:
                if self._proc.stdout is None:
                    break
                chunk = self._proc.stdout.readline()
                if chunk == "" and self._proc.poll() is not None:
                    break
                if chunk:
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
    ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    CONTROL_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]')

    PROGRESS_RE = re.compile(r'(\d{1,9})/(\d{1,9})\s+keys tested.*(?:Time left:\s*([^\r\n]+))?', re.IGNORECASE)
    KEY_FOUND_RE = re.compile(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', re.IGNORECASE)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Aircrack-ng / Hashcat GUI (auto .22000)")
        self.resize(980, 640)
        layout = QtWidgets.QVBoxLayout(self)

        # top
        top = QtWidgets.QHBoxLayout()
        self.aircrack_label = QtWidgets.QLabel("")
        top.addWidget(self.aircrack_label)
        self.hashcat_label = QtWidgets.QLabel("")
        top.addWidget(self.hashcat_label)
        top.addStretch()
        self.install_btn = QtWidgets.QPushButton("Check / Install tools")
        self.install_btn.clicked.connect(self.check_install)
        top.addWidget(self.install_btn)
        layout.addLayout(top)

        # backend selection
        backend_h = QtWidgets.QHBoxLayout()
        backend_h.addWidget(QtWidgets.QLabel("Crack backend:"))
        self.backend_group = QtWidgets.QButtonGroup(self)
        self.rb_aircrack = QtWidgets.QRadioButton("aircrack-ng")
        self.rb_hashcat = QtWidgets.QRadioButton("hashcat")
        self.rb_aircrack.setChecked(True)
        self.backend_group.addButton(self.rb_aircrack)
        self.backend_group.addButton(self.rb_hashcat)
        backend_h.addWidget(self.rb_aircrack)
        backend_h.addWidget(self.rb_hashcat)

        backend_h.addSpacing(20)
        backend_h.addWidget(QtWidgets.QLabel("Hashcat device:"))
        self.hashcat_device = QtWidgets.QComboBox()
        self.hashcat_device.addItems(["GPU (default)", "CPU only"])
        self.hashcat_device.setEnabled(False)
        backend_h.addWidget(self.hashcat_device)
        layout.addLayout(backend_h)

        # form
        form = QtWidgets.QFormLayout()
        self.capture_edit = QtWidgets.QLineEdit()
        self.capture_btn = QtWidgets.QPushButton("Choose capture / hash file")
        self.capture_btn.clicked.connect(self.select_capture)
        h1 = QtWidgets.QHBoxLayout(); h1.addWidget(self.capture_edit); h1.addWidget(self.capture_btn)
        form.addRow("Capture / Hash file:", h1)

        self.wordlist_edit = QtWidgets.QLineEdit()
        self.wordlist_btn = QtWidgets.QPushButton("Choose wordlist")
        self.wordlist_btn.clicked.connect(self.select_wordlist)
        h2 = QtWidgets.QHBoxLayout(); h2.addWidget(self.wordlist_edit); h2.addWidget(self.wordlist_btn)
        form.addRow("Wordlist:", h2)

        self.bssid_edit = QtWidgets.QLineEdit()
        self.bssid_edit.setPlaceholderText("Optional: 00:11:22:33:44:55")
        form.addRow("BSSID (optional, aircrack only):", self.bssid_edit)

        self.hashmode_edit = QtWidgets.QLineEdit()
        self.hashmode_edit.setPlaceholderText("Leave empty to auto-select (22000 preferred).")
        form.addRow("Hashcat mode (numeric):", self.hashmode_edit)

        layout.addLayout(form)

        # buttons
        btn_h = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start")
        self.start_btn.clicked.connect(self.start_crack)
        btn_h.addWidget(self.start_btn)
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_crack)
        btn_h.addWidget(self.stop_btn)
        btn_h.addStretch()
        layout.addLayout(btn_h)

        # output
        self.output = QtWidgets.QPlainTextEdit()
        self.output.setReadOnly(True)
        font = QtGui.QFont("Monospace")
        font.setStyleHint(QtGui.QFont.TypeWriter)
        self.output.setFont(font)
        layout.addWidget(self.output)

        self.status = QtWidgets.QLabel("Ready")
        layout.addWidget(self.status)

        # signals
        self.rb_hashcat.toggled.connect(self.on_backend_toggled)

        self.worker = None
        self.log_lines = []
        self.start_time = None
        self.created_files = []
        self.check_tools_presence()

    def check_tools_presence(self):
        path_air = shutil.which("aircrack-ng")
        if path_air:
            self.aircrack_label.setText(f"aircrack-ng: {path_air}")
            self.aircrack_label.setStyleSheet("color: green")
        else:
            self.aircrack_label.setText("aircrack-ng not found")
            self.aircrack_label.setStyleSheet("color: red")

        path_hashcat = shutil.which("hashcat")
        if path_hashcat:
            self.hashcat_label.setText(f"hashcat: {path_hashcat}")
            self.hashcat_label.setStyleSheet("color: green")
        else:
            self.hashcat_label.setText("hashcat not found")
            self.hashcat_label.setStyleSheet("color: red")

    def check_install(self):
        dlg = QtWidgets.QMessageBox.question(
            self, "Install",
            "This will run: sudo apt update && sudo apt install -y aircrack-ng hashcat\nContinue?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
        )
        if dlg == QtWidgets.QMessageBox.Yes:
            cmd = "sudo apt update && sudo apt install -y aircrack-ng hashcat"
            try:
                p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                QtWidgets.QMessageBox.information(self, "Output", p.stdout[:10000] or "Done")
                self.check_tools_presence()
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "Error", str(e))

    def on_backend_toggled(self, checked):
        self.hashcat_device.setEnabled(self.rb_hashcat.isChecked())

    def select_capture(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Choose capture or hash file",
            "",
            "Handshake / Capture Files (*.cap *.pcap *.pcapng *.hccap *.hccapx *.22000 *.hc22000);;All files (*)"
        )
        if path:
            self.capture_edit.setText(path)

    def select_wordlist(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose wordlist", "", "Text Files (*.txt *.lst);;All files (*)")
        if path:
            self.wordlist_edit.setText(path)

    # cleaning
    def clean_ansi(self, text: str) -> str:
        s = text.replace("\r", "")
        s = self.ANSI_RE.sub("", s)
        s = self.CONTROL_RE.sub("", s)
        return s

    def parse_progress(self, text: str):
        m = self.PROGRESS_RE.search(text)
        if not m:
            return None
        tested = int(m.group(1)); total = int(m.group(2))
        eta = m.group(3) or ""
        pct = (tested / total) * 100 if total > 0 else 0.0
        return tested, total, pct, eta.strip()

    def parse_key_found(self, text: str):
        m = self.KEY_FOUND_RE.search(text)
        if m:
            return m.group(1).strip()
        m2 = re.search(r'Recovered:\s*(\d+)', text, re.IGNORECASE)
        if m2:
            return f"Recovered: {m2.group(1)}"
        return None

    def format_elapsed(self, seconds: float) -> str:
        if seconds is None:
            return "00:00:00"
        seconds = int(seconds)
        h = seconds // 3600; m = (seconds % 3600) // 60; s = seconds % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

    def append_plain(self, text: str):
        self.log_lines.append(text)
        self.output.appendPlainText(text)

    def append_highlight(self, text: str):
        self.log_lines.append(text)
        self.output.appendPlainText(">>> " + text)

    # start / stop
    def start_crack(self):
        backend = "hashcat" if self.rb_hashcat.isChecked() else "aircrack"
        cap = self.capture_edit.text().strip()
        wl = self.wordlist_edit.text().strip()

        if not cap or not os.path.isfile(cap):
            QtWidgets.QMessageBox.warning(self, "Missing file", "Please choose a valid capture / hash file.")
            return
        if not wl or not os.path.isfile(wl):
            QtWidgets.QMessageBox.warning(self, "Missing wordlist", "Please choose a valid wordlist file.")
            return

        self.output.clear(); self.log_lines = []
        self.start_time = time.time()
        self.status.setText(f"Running ({backend})... elapsed: 00:00:00")
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)

        if backend == "aircrack":
            cmd = ["aircrack-ng", "-w", wl, cap]
            bssid = self.bssid_edit.text().strip()
            if bssid:
                cmd.extend(["-b", bssid])
            self.worker = Worker(cmd)
            self.worker.output_line.connect(self.on_output_line)
            self.worker.finished_signal.connect(self.on_finished)
            self.worker.start()
            return

        # hashcat path
        chosen_device = self.hashcat_device.currentText()
        cpu_only = (chosen_device.lower().find("cpu") >= 0)

        _, ext = os.path.splitext(cap.lower())
        prepared_hashfile = None
        self.created_files = []

        try:
            # if already a hash file
            if ext in (".hccapx", ".hccap", ".22000", ".hc22000"):
                prepared_hashfile = cap
                original_cap = cap  # keep for potential conversion attempts
            elif ext in (".cap", ".pcap", ".pcapng"):
                original_cap = cap
                base = os.path.splitext(os.path.basename(cap))[0]
                cwd = os.getcwd()
                prefix = os.path.join(cwd, f"{base}_conv")
                try:
                    self.append_plain(f"[Converting capture using aircrack-ng -J -> {prefix}.hccapx / {prefix}.hccap ...]")
                    conv_cmd = ["aircrack-ng", "-J", prefix, cap]
                    p = subprocess.run(conv_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    self.append_plain(p.stdout.strip())

                    candidate_x = prefix + ".hccapx"
                    candidate = prefix + ".hccap"
                    if os.path.isfile(candidate_x):
                        prepared_hashfile = candidate_x
                        self.created_files.append(candidate_x)
                        self.append_plain(f"[Created {candidate_x}]")
                    elif os.path.isfile(candidate):
                        prepared_hashfile = candidate
                        self.created_files.append(candidate)
                        self.append_plain(f"[Created {candidate}]")
                    else:
                        # try cap2hccapx
                        if shutil.which("cap2hccapx"):
                            out_hccapx = os.path.join(cwd, f"{base}.hccapx")
                            self.append_plain(f"[Trying cap2hccapx -> {out_hccapx} ...]")
                            c2_cmd = ["cap2hccapx", cap, out_hccapx]
                            p2 = subprocess.run(c2_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                            self.append_plain(p2.stdout.strip())
                            if os.path.isfile(out_hccapx):
                                prepared_hashfile = out_hccapx
                                self.created_files.append(out_hccapx)
                                self.append_plain(f"[Created {out_hccapx}]")
                        # fallback: try hcxpcapngtool -> .22000 (preferred)
                        if not prepared_hashfile and shutil.which("hcxpcapngtool"):
                            out_22000 = os.path.join(cwd, f"{base}.22000")
                            self.append_plain(f"[Trying hcxpcapngtool -> {out_22000} ...]")
                            hcx_cmd = ["hcxpcapngtool", "-o", out_22000, cap]
                            p3 = subprocess.run(hcx_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                            self.append_plain(p3.stdout.strip())
                            if os.path.isfile(out_22000):
                                prepared_hashfile = out_22000
                                self.created_files.append(out_22000)
                                self.append_plain(f"[Created {out_22000}]")
                except Exception as e:
                    self.append_plain(f"[Conversion error: {e}]")

                if not prepared_hashfile:
                    QtWidgets.QMessageBox.warning(self, "Conversion failed",
                                                  "Could not convert capture to .hccap/.hccapx or .22000 automatically.\n"
                                                  "Please convert manually and provide a supported file.")
                    self.status.setText("Ready")
                    self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
                    self.start_time = None
                    return
            else:
                prepared_hashfile = cap
                original_cap = cap

            # If we have a .hccap/.hccapx, try to auto-create .22000 (preferred)
            pext = os.path.splitext(prepared_hashfile.lower())[1]
            if pext in (".hccap", ".hccapx") and shutil.which("hcxpcapngtool"):
                base2 = os.path.splitext(os.path.basename(original_cap))[0]
                out_22000 = os.path.join(os.getcwd(), f"{base2}.22000")
                try:
                    self.append_plain(f"[Auto-converting {os.path.basename(prepared_hashfile)} -> {out_22000} using hcxpcapngtool...]")
                    # hcxpcapngtool works on cap/pcapng; pass original cap for best results
                    hcx_cmd = ["hcxpcapngtool", "-o", out_22000, original_cap]
                    p4 = subprocess.run(hcx_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    self.append_plain(p4.stdout.strip())
                    if os.path.isfile(out_22000):
                        prepared_hashfile = out_22000
                        self.created_files.append(out_22000)
                        self.append_plain(f"[Created {out_22000}] (will use mode 22000)")
                except Exception as e:
                    self.append_plain(f"[Auto-convert to .22000 failed: {e}]")

            # Auto-select hash mode if user left it empty
            user_hashmode = self.hashmode_edit.text().strip()
            if user_hashmode:
                hashmode = user_hashmode
            else:
                _, pext2 = os.path.splitext(prepared_hashfile.lower())
                if pext2 in (".22000", ".hc22000"):
                    hashmode = "22000"
                elif pext2 in (".hccap", ".hccapx"):
                    hashmode = "2500"
                    self.append_plain("[Note] Auto-selected hash mode 2500 for .hccap/.hccapx (deprecated).")
                else:
                    hashmode = "22000"

            cmd = ["hashcat", "-m", str(hashmode), "-a", "0", prepared_hashfile, wl,
                   "--potfile-path", os.path.join(tempfile.gettempdir(), "hashcat_gui.potfile")]
            if cpu_only:
                cmd.extend(["--opencl-device-types", "1"])

            self.append_plain(f"[Starting hashcat with mode {hashmode} on {os.path.basename(prepared_hashfile)}]")
            self.worker = Worker(cmd)
            self.worker.output_line.connect(self.on_output_line)
            self.worker.finished_signal.connect(self.on_finished)
            self.worker.start()

        except Exception as e:
            self.append_plain(f"[ERROR starting hashcat: {e}]")
            self.status.setText("Error")
            self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
            self.start_time = None

    def stop_crack(self):
        if self.worker:
            self.worker.stop()
            self.append_plain("[Requested stop]")
            self.status.setText("Stopping...")

    # output handling
    def on_output_line(self, raw_line: str):
        line = self.clean_ansi(raw_line).strip()
        if not line:
            return

        elapsed_str = "00:00:00"
        if self.start_time:
            elapsed_str = self.format_elapsed(time.time() - self.start_time)

        key = self.parse_key_found(line)
        if key:
            self.append_highlight(f"KEY FOUND / RECOVERED: {key} (elapsed: {elapsed_str})")
            self.status.setText(f"KEY FOUND (elapsed: {elapsed_str})")
            return

        prog = self.parse_progress(line)
        if prog:
            tested, total, pct, eta = prog
            pct_str = f"{pct:0.2f}%"
            short = f"Progress: {tested}/{total} keys ({pct_str})"
            if eta:
                short += f" — ETA: {eta}"
            short += f" — elapsed: {elapsed_str}"
            self.append_plain(short)
            self.status.setText(short)
            return

        if re.search(r'Read\s+\d+\s+packets', line, re.IGNORECASE) or \
           re.search(r'potential targets', line, re.IGNORECASE) or \
           re.search(r'Opening\s+.+', line, re.IGNORECASE) or \
           re.search(r'Resetting EAPOL Handshake decoder', line, re.IGNORECASE) or \
           re.search(r'Time left:', line, re.IGNORECASE) or \
           re.search(r'Current passphrase:', line, re.IGNORECASE) or \
           re.search(r'Recovered', line, re.IGNORECASE) or \
           re.search(r'Status.*:\s*', line, re.IGNORECASE):
            self.append_plain(f"{line}  (elapsed: {elapsed_str})")
            return

        if re.match(r'^[0-9A-Fa-f ]{20,}$', line.replace(" ", "")):
            return

        self.append_plain(f"{line}  (elapsed: {elapsed_str})")

    def on_finished(self, rc):
        total_elapsed_str = "00:00:00"
        if self.start_time:
            total_elapsed_str = self.format_elapsed(time.time() - self.start_time)

        self.append_plain(f"[Process exited with code {rc}] — Total time: {total_elapsed_str}")
        self.status.setText("Finished" if rc == 0 else f"Exited ({rc})")
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.worker = None
        self.start_time = None

        # created conversion files remain in cwd (self.created_files).
        # Optionally delete them after success (uncomment to enable):
        # for f in self.created_files:
        #     try:
        #         os.remove(f)
        #         self.append_plain(f"[Removed conversion file {f}]")
        #     except Exception:
        #         pass
        # self.created_files = []

# run
def main():
    app = QtWidgets.QApplication(sys.argv)
    win = AircrackGui()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
