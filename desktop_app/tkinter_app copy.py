# (Toàn bộ file - phần trước giống bạn, mình chỉ chèn/ẩn thêm phần hashcat UI và logic)
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import datetime
import os
import subprocess
import shutil
import random
from typing import List
import re
import tempfile
import csv

APP_TITLE = "Wi-Fi Security Tool"


class DesktopApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x520")
        # scanning / capturing state
        self.scanning = False
        self.scan_proc = None
        self.scan_tmpdir = None
        self.scan_prefix = None

        self.capturing = False
        self.capture_proc = None
        self.capture_tmpdir = None
        self.capture_prefix = None
        self.stop_capture_event = threading.Event()
        self.deauth_thread = None

        # hashcat related
        self.hashfile_path = None  # user-selected hash file (e.g., .hccapx or hash list)

        self._build_ui()

    def _build_ui(self):
        left = ttk.Frame(self)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=8)
        ttk.Label(left, text="Detected networks (ESSID | BSSID | CH | Signal)").pack(anchor=tk.W)

        # Interface selector + refresh
        ttk.Label(left, text="Select interface:").pack(anchor=tk.W, pady=(6,0))
        iface_frame = ttk.Frame(left)
        iface_frame.pack(fill=tk.X)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(iface_frame, textvariable=self.iface_var, values=[])
        self.iface_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.iface_refresh_btn = ttk.Button(iface_frame, text="Refresh", command=self.populate_interfaces)
        self.iface_refresh_btn.pack(side=tk.LEFT, padx=(6,0))
        # widen list for readability
        self.net_listbox = tk.Listbox(left, width=80, height=12)
        self.net_listbox.pack(pady=6)

        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill=tk.X, pady=6)

        self.scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.capture_btn = ttk.Button(btn_frame, text="Capture Handshake", command=self.toggle_capture)
        self.capture_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.crack_btn = ttk.Button(left, text="Crack (simulate)", command=self.start_crack)
        self.crack_btn.pack(fill=tk.X, pady=(6,0))

        # Hashcat UI
        ttk.Label(left, text="--- Hashcat cracking ---").pack(anchor=tk.W, pady=(8,0))
        hash_frame = ttk.Frame(left)
        hash_frame.pack(fill=tk.X)

        self.hashfile_entry = ttk.Entry(hash_frame)
        self.hashfile_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        hf_btn = ttk.Button(hash_frame, text="Select Hash File", command=self.select_hashfile)
        hf_btn.pack(side=tk.LEFT, padx=(6,0))

        hc_opts_frame = ttk.Frame(left)
        hc_opts_frame.pack(fill=tk.X, pady=(6,0))
        ttk.Label(hc_opts_frame, text="Mode:").pack(side=tk.LEFT)
        self.hashmode_var = tk.StringVar(value="2500")
        self.hashmode_entry = ttk.Entry(hc_opts_frame, width=8, textvariable=self.hashmode_var)
        self.hashmode_entry.pack(side=tk.LEFT, padx=(6,8))
        ttk.Label(hc_opts_frame, text="Wordlist:").pack(side=tk.LEFT)
        self.hc_wordlist_var = tk.StringVar()
        self.hc_wordlist_entry = ttk.Entry(hc_opts_frame, textvariable=self.hc_wordlist_var)
        self.hc_wordlist_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6,0))
        hc_wl_btn = ttk.Button(hc_opts_frame, text="Browse", command=self.select_hc_wordlist)
        hc_wl_btn.pack(side=tk.LEFT, padx=(6,0))

        hc_run_frame = ttk.Frame(left)
        hc_run_frame.pack(fill=tk.X, pady=(6,0))
        self.hc_args_entry = ttk.Entry(hc_run_frame)
        self.hc_args_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.hc_run_btn = ttk.Button(hc_run_frame, text="Crack with Hashcat", command=self.run_hashcat_ui)
        self.hc_run_btn.pack(side=tk.LEFT, padx=(6,0))

        save_btn = ttk.Button(left, text="Save Output...", command=self.save_output)
        save_btn.pack(fill=tk.X, pady=(6,0))
        # Wordlist selection (for aircrack)
        ttk.Label(left, text="Wordlist (for aircrack-ng):").pack(anchor=tk.W, pady=(8,0))
        wl_frame = ttk.Frame(left)
        wl_frame.pack(fill=tk.X)
        self.wordlist_var = tk.StringVar()
        self.wordlist_entry = ttk.Entry(wl_frame, textvariable=self.wordlist_var)
        self.wordlist_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        wl_btn = ttk.Button(wl_frame, text="Browse", command=self.select_wordlist)
        wl_btn.pack(side=tk.LEFT, padx=(6,0))

        # Command runner UI
        ttk.Label(left, text="Run whitelisted command:").pack(anchor=tk.W, pady=(8,0))
        cmd_frame = ttk.Frame(left)
        cmd_frame.pack(fill=tk.X)

        # whitelist similar to server
        self.ALLOWED_COMMANDS = [
            "iwconfig",
            "iw",
            "iwlist",
            "ifconfig",
            "airmon-ng",
            "airodump-ng",
            "aireplay-ng",
            "aircrack-ng",
            "timeout",
            "ls",
            "pwd",
            "whoami",
        ]

        self.cmd_var = tk.StringVar()
        self.cmd_combo = ttk.Combobox(cmd_frame, textvariable=self.cmd_var, values=self.ALLOWED_COMMANDS)
        self.cmd_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.args_entry = ttk.Entry(cmd_frame)
        self.args_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6,0))

        self.run_btn = ttk.Button(left, text="Run", command=self.run_selected_command)
        self.run_btn.pack(fill=tk.X, pady=(6,0))

        right = ttk.Frame(self)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=8, pady=8)

        ttk.Label(right, text="Terminal output").pack(anchor=tk.W)
        self.output = tk.Text(right, wrap="word")
        self.output.pack(fill=tk.BOTH, expand=True)

        # initial state
        self.last_capture_path = None
        self.log("App started")
        # populate interfaces on startup
        self.populate_interfaces()

    # ----------------- file selectors -----------------
    def select_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist file", filetypes=[("Wordlist", "*.*")])
        if path:
            self.wordlist_var.set(path)
            self.log(f"Selected wordlist: {path}")

    def select_hashfile(self):
        path = filedialog.askopenfilename(title="Select hash file (hccapx / hash list)", filetypes=[("Hash files", "*.*")])
        if path:
            self.hashfile_path = path
            self.hashfile_entry.delete(0, tk.END)
            self.hashfile_entry.insert(0, path)
            self.log(f"Selected hash file: {path}")

    def select_hc_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist for hashcat", filetypes=[("Wordlist", "*.*")])
        if path:
            self.hc_wordlist_var.set(path)
            self.log(f"Selected hashcat wordlist: {path}")

    # ----------------- other helpers -----------------
    def populate_interfaces(self):
        interfaces = []
        try:
            exe = shutil.which("iwconfig")
            if exe:
                proc = subprocess.Popen([exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=3)
                for line in out.splitlines():
                    if not line:
                        continue
                    if not line.startswith(" "):
                        parts = line.split()
                        if parts:
                            name = parts[0]
                            interfaces.append(name)
        except Exception:
            interfaces = []

        if not interfaces:
            try:
                netdir = "/sys/class/net"
                if os.path.isdir(netdir):
                    interfaces = [n for n in os.listdir(netdir) if os.path.isdir(os.path.join(netdir, n))]
            except Exception:
                interfaces = []

        def update_ifaces():
            self.iface_combo["values"] = interfaces
            if interfaces:
                cur = self.iface_var.get()
                if not cur or cur not in interfaces:
                    self.iface_var.set(interfaces[0])
                self.log(f"Interfaces: {', '.join(interfaces)}")
            else:
                self.iface_var.set("")
                self.log("No interfaces detected")

        self.after(0, update_ifaces)

    def _is_pcap(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                hdr = f.read(4)
                if len(hdr) < 4:
                    return False
                magic = hdr
                if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
                    return True
                if magic == b"\x0a\x0d\x0d\x0a":
                    return True
        except Exception:
            return False
        return False

    def log(self, msg: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.output.insert(tk.END, f"[{ts}] {msg}\n")
        self.output.see(tk.END)

    # ----------------- command runner -----------------
    def run_selected_command(self):
        cmd = self.cmd_var.get().strip()
        if not cmd:
            messagebox.showinfo("No command", "Please select a command to run.")
            return
        if cmd not in self.ALLOWED_COMMANDS:
            messagebox.showerror("Not allowed", f"Command '{cmd}' is not allowed by the whitelist.")
            return
        raw_args = self.args_entry.get().strip()
        args = raw_args.split() if raw_args else []
        t = threading.Thread(target=self._run_command, args=(cmd, args))
        t.daemon = True
        t.start()

    def _run_command(self, command: str, args: List[str]):
        exe = shutil.which(command)
        if not exe:
            self.log(f"Command not found in PATH: {command}")
            return

        self.log(f"Running: {command} {' '.join(args)}")
        try:
            proc = subprocess.Popen([exe] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            def stream(pipe, name):
                for line in iter(pipe.readline, ""):
                    if not line:
                        break
                    self.after(0, lambda l=line.rstrip(): self.log(f"{name}: {l}"))
                pipe.close()

            threads = []
            t_out = threading.Thread(target=stream, args=(proc.stdout, "OUT"))
            t_err = threading.Thread(target=stream, args=(proc.stderr, "ERR"))
            t_out.start(); t_err.start()
            threads.extend([t_out, t_err])

            code = proc.wait()
            for t in threads:
                t.join(timeout=0.1)

            self.log(f"Process exited with code: {code}")
        except Exception as e:
            self.log(f"Failed to run command: {e}")

    # ----------------- scanning (unchanged) -----------------
    def start_scan(self):
        if not self.scanning:
            t = threading.Thread(target=self._start_airodump_scan)
            t.daemon = True
            t.start()
        else:
            self._stop_airodump_scan()

    def _start_airodump_scan(self):
        iface = self.iface_var.get().strip()
        if not iface:
            self.log("No interface selected for scan")
            return

        airodump_exe = shutil.which("airodump-ng")
        if not airodump_exe:
            self.log("airodump-ng not available; falling back to quick scan (iw/iwlist)")
            self._scan()
            return

        tmp = tempfile.mkdtemp(prefix="airodump_")
        prefix = os.path.join(tmp, "dump")
        self.scan_tmpdir = tmp
        self.scan_prefix = prefix

        cmd = ["sudo", airodump_exe, "--write-interval", "1", "--output-format", "csv", "-w", prefix, iface]
        self.log(f"Starting airodump-ng scan: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as e:
            self.log(f"Failed to start airodump-ng: {e}")
            return

        self.scan_proc = proc
        self.scanning = True

        def set_btn_stop():
            self.scan_btn.config(text="Stop Scan")
        self.after(0, set_btn_stop)

        def drain_streams(p):
            try:
                for line in iter(p.stdout.readline, ""):
                    if not line:
                        break
                    self.after(0, lambda l=line.rstrip(): self.log(f"airodump: {l}"))
                p.stdout.close()
            except Exception:
                pass
            try:
                for line in iter(p.stderr.readline, ""):
                    if not line:
                        break
                    self.after(0, lambda l=line.rstrip(): self.log(f"airodump-err: {l}"))
                p.stderr.close()
            except Exception:
                pass

        t = threading.Thread(target=drain_streams, args=(proc,))
        t.daemon = True
        t.start()

        try:
            while self.scanning and proc.poll() is None:
                csv_path = prefix + "-01.csv"
                if os.path.exists(csv_path):
                    try:
                        nets = self._parse_airodump_csv(csv_path)
                        def update_list():
                            self.net_listbox.delete(0, tk.END)
                            for n in nets:
                                name = n.get("essid") or "<hidden>"
                                b = n.get("bssid") or "00:00:00:00:00:00"
                                ch = n.get("channel") or "?"
                                pwr = n.get("power")
                                sig_text = f"{pwr} dBm" if pwr is not None else ""
                                display = f"{name}  |  {b}  |  CH:{ch}"
                                if sig_text:
                                    display += f"  |  {sig_text}"
                                self.net_listbox.insert(tk.END, display)
                            self.log(f"Scan update: {len(nets)} networks")
                        self.after(0, update_list)
                    except Exception as e:
                        self.log(f"Failed to parse CSV: {e}")
                time.sleep(1.0)

        finally:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
            self.scanning = False
            self.scan_proc = None
            def set_btn_start():
                self.scan_btn.config(text="Start Scan")
            self.after(0, set_btn_start)
            self.log("Airodump scan stopped")

    def _stop_airodump_scan(self):
        if not self.scanning and not self.scan_proc:
            self.log("No active scan to stop")
            return
        self.log("Stopping scan...")
        self.scanning = False
        if self.scan_proc and self.scan_proc.poll() is None:
            try:
                self.scan_proc.terminate()
            except Exception:
                pass
        self.scan_proc = None

    def _parse_airodump_csv(self, csv_path: str):
        rows = []
        try:
            with open(csv_path, newline='', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                rows = [r for r in reader]
        except Exception as e:
            raise

        header_idx = None
        header = None
        for i, r in enumerate(rows):
            if any((cell or '').strip().lower() == 'bssid' for cell in r):
                header_idx = i
                header = [ (cell or '').strip().lower() for cell in r ]
                break

        if header_idx is None or header is None:
            return []

        networks = []
        for r in rows[header_idx+1:]:
            if not r:
                break
            first = (r[0] or '').strip().lower()
            if first.startswith('station mac') or first.startswith('station'):
                break
            if not (r[0] or '').strip():
                break

            if len(r) < len(header):
                r = r + [''] * (len(header) - len(r))

            idx = {h: idx for idx, h in enumerate(header)}
            bssid = r[idx.get('bssid', 0)].strip()
            essid = r[idx.get('essid', len(r)-1)].strip() if 'essid' in idx else r[-1].strip()
            channel = r[idx.get('channel', '')].strip() if 'channel' in idx else ''
            power = None
            for key in ('power', 'pwr'):
                if key in idx:
                    val = (r[idx[key]] or '').strip()
                    try:
                        power = int(val)
                    except Exception:
                        power = None
                    break

            networks.append({'bssid': bssid, 'essid': essid, 'channel': channel, 'power': power})

        return networks

    def _scan(self):
        self.log("Starting quick scan...")
        iface = self.iface_var.get().strip()
        if not iface:
            self.log("No interface selected for scan")
            return

        nets = []
        try:
            iw_exe = shutil.which("iw")
            if iw_exe:
                proc = subprocess.Popen([iw_exe, "dev", iface, "scan"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=8)
                bssid = None
                ssid = None
                sig = None
                for line in out.splitlines():
                    line = line.strip()
                    m = re.match(r"^BSS\s+([0-9a-f:]{17})", line, re.I)
                    if m:
                        if bssid is not None:
                            nets.append((ssid if ssid is not None else "", bssid, sig if sig is not None else ""))
                        bssid = m.group(1)
                        ssid = ""
                        sig = None
                        continue
                    if line.startswith("SSID:"):
                        ssid = line.split("SSID:", 1)[1].strip()
                    elif line.startswith("signal:"):
                        m2 = re.search(r"([-0-9.]+)", line)
                        if m2:
                            try:
                                sig = int(float(m2.group(1)))
                            except Exception:
                                sig = None
                if bssid is not None:
                    nets.append((ssid if ssid is not None else "", bssid, sig if sig is not None else ""))
        except Exception:
            pass

        if not nets:
            try:
                iwlist_exe = shutil.which("iwlist")
                if iwlist_exe:
                    proc = subprocess.Popen([iwlist_exe, iface, "scan"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    out, err = proc.communicate(timeout=8)
                    bssid = None
                    ssid = None
                    sig = None
                    for line in out.splitlines():
                        line = line.strip()
                        m = re.match(r"^Cell\s+\d+\s+-\s+Address:\s*([0-9A-Fa-f:]{17})", line)
                        if m:
                            if bssid is not None:
                                nets.append((ssid if ssid is not None else "", bssid, sig if sig is not None else ""))
                            bssid = m.group(1)
                            ssid = ""
                            sig = None
                            continue
                        if "ESSID:" in line:
                            m2 = re.search(r'ESSID:"(.*)"', line)
                            if m2:
                                ssid = m2.group(1)
                        if "Signal level" in line:
                            m3 = re.search(r"Signal level=([-0-9]+)\s*dBm", line)
                            if m3:
                                try:
                                    sig = int(m3.group(1))
                                except Exception:
                                    sig = None
                    if bssid is not None:
                        nets.append((ssid if ssid is not None else "", bssid, sig if sig is not None else ""))
            except Exception:
                pass

        if not nets:
            self.log("No networks found via system scan; falling back to simulated scan")
            time.sleep(1)
            for i in range(random.randint(4, 8)):
                ssid = f"Network_{random.randint(100,999)}"
                bssid = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
                sig = random.randint(-90, -30)
                nets.append((ssid, bssid, sig))

        def update():
            self.net_listbox.delete(0, tk.END)
            for s, b, sig in nets:
                name = s if (s is not None and s != "") else "<hidden>"
                sig_text = f"{sig} dBm" if sig != "" and sig is not None else ""
                display = f"{name}  |  {b}"
                if sig_text:
                    display += f"  |  {sig_text}"
                self.net_listbox.insert(tk.END, display)
            self.log(f"Scan complete: {len(nets)} networks found")

        self.after(0, update)

    # --- Capture logic unchanged (use your existing capture code) ---
    # For brevity, assume your existing _capture/_stop logic is here and unchanged.
    # (You can paste your _capture implementation from previous code; left out here for compactness.)
    # But in this file you should keep the previously working _capture implementation.

    # ----------------- Crack (aircrack) -----------------
    def start_crack(self):
        sel = self.net_listbox.curselection()
        if not sel:
            messagebox.showinfo("No network selected", "Please select a network to crack (simulated).")
            return
        t = threading.Thread(target=self._crack, args=(sel[0],))
        t.daemon = True
        t.start()

    def _crack(self, index):
        self.crack_btn.config(state=tk.DISABLED)
        self.log("Starting cracking routine...")
        overall_start = time.time()

        try:
            proc_path = shutil.which("aircrack-ng")
        except Exception:
            proc_path = None

        if proc_path:
            self.log("aircrack-ng found, running real command (will prompt for .cap and wordlist if needed)")
            self.log(f"aircrack-ng path: {proc_path}")

            cap = self.last_capture_path
            if not cap or not os.path.exists(cap):
                cap = filedialog.askopenfilename(title="Select capture file (.cap)", filetypes=[("Capture files", "*.cap"), ("All files", "*.*")])
                if not cap:
                    self.log("No capture file provided. Aborting real crack.")
                    self.crack_btn.config(state=tk.NORMAL)
                    return

            wordlist = self.wordlist_var.get().strip()
            if not wordlist or not os.path.exists(wordlist):
                wordlist = filedialog.askopenfilename(title="Select wordlist file", filetypes=[("Wordlist", "*.*")])
                if not wordlist:
                    self.log("No wordlist provided. Aborting real crack.")
                    self.crack_btn.config(state=tk.NORMAL)
                    return

            try:
                exe = proc_path
                self.log(f"Running: {exe} -w {wordlist} {cap}")
                p = subprocess.Popen([exe, "-w", wordlist, cap], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                def stream(pipe, name):
                    for line in iter(pipe.readline, ""):
                        if not line:
                            break
                        self.after(0, lambda l=line.rstrip(): self.log(f"{name}: {l}"))
                    pipe.close()

                t_out = threading.Thread(target=stream, args=(p.stdout, "OUT"))
                t_err = threading.Thread(target=stream, args=(p.stderr, "ERR"))
                t_out.start(); t_err.start()
                code = p.wait()
                t_out.join(timeout=0.1); t_err.join(timeout=0.1)
                end_time = time.time()
                elapsed = end_time - overall_start
                self.log(f"aircrack-ng exited with code: {code}")
                self.log(f"Crack finished in {elapsed:.2f}s")
                messagebox.showinfo("Crack finished", f"aircrack-ng exited with code {code}\nTime: {elapsed:.2f}s")
            except Exception as e:
                self.log(f"Failed to run aircrack-ng: {e}")
            time.sleep(0.2)
        else:
            steps = 6
            for i in range(steps):
                time.sleep(0.9)
                pct = int((i+1)/steps*100)
                self.log(f"Cracking... {pct}%")

            end_time = time.time()
            elapsed = end_time - overall_start

            if random.random() < 0.35:
                key = "correcthorsebatterystaple"
                self.log(f"Key found: {key}")
                self.log(f"Crack finished in {elapsed:.2f}s")
                messagebox.showinfo("Crack result", f"Key found: {key}\nTime: {elapsed:.2f}s")
            else:
                self.log("Key not found (simulated)")
                self.log(f"Crack finished in {elapsed:.2f}s")
                messagebox.showinfo("Crack result", f"Key not found (simulated)\nTime: {elapsed:.2f}s")

        self.crack_btn.config(state=tk.NORMAL)

    # ----------------- Hashcat integration -----------------
    def run_hashcat_ui(self):
        """Start hashcat cracking in background thread (UI wrapper)."""
        # If no hash file selected but we have last_capture_path, attempt conversion later
        t = threading.Thread(target=self._run_hashcat_thread)
        t.daemon = True
        t.start()

    def _try_convert_cap_to_hccapx(self, cap_path: str):
        """
        Try best-effort to convert .cap to .hccapx using common tools on PATH:
          - cap2hccapx (from hashcat-utils) -> cap2hccapx
          - hcxpcaptool (from hcxtools) -> hcxpcaptool -o out.hccapx in.cap
        Returns path to hccapx or None.
        """
        if not cap_path or not os.path.exists(cap_path):
            return None
        # prefer hcxpcaptool (newer)
        hcx = shutil.which("hcxpcaptool")
        if hcx:
            out = os.path.splitext(cap_path)[0] + ".hccapx"
            try:
                rc = subprocess.run([hcx, "-o", out, cap_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
                if os.path.exists(out):
                    self.log(f"Converted {cap_path} -> {out} using hcxpcaptool")
                    return out
            except Exception as e:
                self.log(f"hcxpcaptool conversion failed: {e}")
        cap2 = shutil.which("cap2hccapx.bin") or shutil.which("cap2hccapx")
        if cap2:
            out = os.path.splitext(cap_path)[0] + ".hccapx"
            try:
                rc = subprocess.run([cap2, cap_path, out], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
                if os.path.exists(out):
                    self.log(f"Converted {cap_path} -> {out} using cap2hccapx")
                    return out
            except Exception as e:
                self.log(f"cap2hccapx conversion failed: {e}")
        return None

    def _run_hashcat_thread(self):
        """Core logic to run hashcat and log output."""
        # disable button
        self.hc_run_btn.config(state=tk.DISABLED)
        start_time = time.time()

        hc_exec = shutil.which("hashcat")
        if not hc_exec:
            self.log("hashcat not found in PATH. Install hashcat or add to PATH.")
            messagebox.showerror("Hashcat missing", "hashcat not found in PATH. Please install hashcat.")
            self.hc_run_btn.config(state=tk.NORMAL)
            return

        # determine hash file
        hashfile = self.hashfile_path or (self.hashfile_entry.get().strip() or None)
        if not hashfile and self.last_capture_path and os.path.exists(self.last_capture_path):
            # try to convert .cap -> .hccapx
            self.log("No hash file selected; attempting to convert last capture to hccapx (if tools available)...")
            conv = self._try_convert_cap_to_hccapx(self.last_capture_path)
            if conv:
                hashfile = conv
            else:
                self.log("Conversion not available or failed. Prompting user for hash file.")
        if not hashfile:
            hashfile = filedialog.askopenfilename(title="Select hash file for hashcat (hccapx / hash list)", filetypes=[("Hash files", "*.*")])
            if not hashfile:
                self.log("No hash file provided. Aborting hashcat run.")
                self.hc_run_btn.config(state=tk.NORMAL)
                return

        if not os.path.exists(hashfile):
            self.log(f"Hash file not found: {hashfile}")
            messagebox.showerror("Hash file missing", f"Hash file not found: {hashfile}")
            self.hc_run_btn.config(state=tk.NORMAL)
            return

        self.hashfile_path = hashfile
        self.hashfile_entry.delete(0, tk.END)
        self.hashfile_entry.insert(0, hashfile)

        # determine wordlist
        wordlist = self.hc_wordlist_var.get().strip()
        if not wordlist or not os.path.exists(wordlist):
            self.log("No wordlist selected for hashcat; prompting user.")
            wl = filedialog.askopenfilename(title="Select wordlist for hashcat", filetypes=[("Wordlist", "*.*")])
            if not wl:
                self.log("No wordlist provided. Aborting hashcat run.")
                self.hc_run_btn.config(state=tk.NORMAL)
                return
            wordlist = wl
            self.hc_wordlist_var.set(wordlist)

        hashmode = self.hashmode_var.get().strip() or "2500"
        extra_args = self.hc_args_entry.get().strip()
        arg_list = extra_args.split() if extra_args else []

        cmd = [hc_exec, "-m", hashmode, hashfile, "-a", "0", wordlist] + arg_list
        self.log(f"Running hashcat: {' '.join(cmd)}")

        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            def stream(pipe, name):
                for line in iter(pipe.readline, ""):
                    if not line:
                        break
                    self.after(0, lambda l=line.rstrip(): self.log(f"{name}: {l}"))
                try:
                    pipe.close()
                except:
                    pass

            t_out = threading.Thread(target=stream, args=(p.stdout, "OUT"), daemon=True)
            t_err = threading.Thread(target=stream, args=(p.stderr, "ERR"), daemon=True)
            t_out.start(); t_err.start()
            code = p.wait()
            t_out.join(timeout=0.1); t_err.join(timeout=0.1)
            end_time = time.time()
            elapsed = end_time - start_time
            self.log(f"Hashcat exited with code: {code}")
            self.log(f"Hashcat run time: {elapsed:.2f}s")
            messagebox.showinfo("Hashcat finished", f"Exit code: {code}\nTime: {elapsed:.2f}s")
        except Exception as e:
            self.log(f"Failed to run hashcat: {e}")
            messagebox.showerror("Hashcat error", f"Failed to run hashcat: {e}")
        finally:
            self.hc_run_btn.config(state=tk.NORMAL)

    # ----------------- save output -----------------
    def save_output(self):
        txt = self.output.get("1.0", tk.END)
        if not txt.strip():
            messagebox.showinfo("No output", "There is no terminal output to save.")
            return
        path = filedialog.asksaveasfilename(title="Save output", defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                                            initialdir=os.getcwd())
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(txt)
        self.log(f"Output saved to: {path}")


if __name__ == '__main__':
    app = DesktopApp()
    app.mainloop()
