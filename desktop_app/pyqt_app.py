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

APP_TITLE = "Wi-Fi Security Tool"


class DesktopApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x520")

        self._build_ui()

    def _build_ui(self):
        left = ttk.Frame(self)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=8)
        ttk.Label(left, text="Detected networks (ESSID | BSSID | Signal)").pack(anchor=tk.W)

        # Interface selector + refresh
        ttk.Label(left, text="Select interface:").pack(anchor=tk.W, pady=(6,0))
        iface_frame = ttk.Frame(left)
        iface_frame.pack(fill=tk.X)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(iface_frame, textvariable=self.iface_var, values=[])
        self.iface_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.iface_refresh_btn = ttk.Button(iface_frame, text="Refresh", command=self.populate_interfaces)
        self.iface_refresh_btn.pack(side=tk.LEFT, padx=(6,0))
        self.net_listbox = tk.Listbox(left, width=36, height=20)
        self.net_listbox.pack(pady=6)

        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill=tk.X, pady=6)

        self.scan_btn = ttk.Button(btn_frame, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.capture_btn = ttk.Button(btn_frame, text="Capture Handshake", command=self.start_capture)
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

        run_btn = ttk.Button(left, text="Run", command=self.run_selected_command)
        run_btn.pack(fill=tk.X, pady=(6,0))

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
        t = threading.Thread(target=self._scan)
        t.daemon = True
        t.start()

    def _scan(self):
        self.scan_btn.config(state=tk.DISABLED)
        self.log("Starting scan...")

        iface = self.iface_var.get().strip()
        if not iface:
            self.log("No interface selected for scan")
            self.scan_btn.config(state=tk.NORMAL)
            return

        nets = []

        # Try 'iw dev <iface> scan' first (modern tool)
        try:
            iw_exe = shutil.which("iw")
            if iw_exe:
                proc = subprocess.Popen([iw_exe, "dev", iface, "scan"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=10)
                bssid = None
                ssid = None
                sig = None
                for line in out.splitlines():
                    line = line.strip()
                    m = re.match(r"^BSS\s+([0-9a-f:]{17})", line, re.I)
                    if m:
                        # commit previous
                        if bssid is not None:
                            # allow hidden ESSID (empty string)
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

        # If no results from iw, try iwlist
        if not nets:
            try:
                iwlist_exe = shutil.which("iwlist")
                if iwlist_exe:
                    proc = subprocess.Popen([iwlist_exe, iface, "scan"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    out, err = proc.communicate(timeout=10)
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

        # Fallback to simulated scan if nothing found
        if not nets:
            self.log("No networks found via system scan; falling back to simulated scan")
            time.sleep(1)
            for i in range(random.randint(4, 10)):
                ssid = f"Network_{random.randint(100,999)}"
                bssid = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
                sig = random.randint(-90, -30)
                nets.append((ssid, bssid, sig))

        # update UI on main thread
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
            self.scan_btn.config(state=tk.NORMAL)

        self.after(0, update)

    def start_capture(self):
        sel = self.net_listbox.curselection()
        if not sel:
            messagebox.showinfo("No network selected", "Please select a network to capture handshake from.")
            return
        t = threading.Thread(target=self._capture, args=(sel[0],))
        t.daemon = True
        t.start()

    def _capture(self, index):
        self.capture_btn.config(state=tk.DISABLED)
        self.log("Starting handshake capture...")

        # Lấy thông tin từ listbox
        try:
            entry = self.net_listbox.get(index)
        except Exception:
            entry = "<unknown> | 00:00:00:00:00:00 | -"
    
        parts = [p.strip() for p in entry.split("|")]
        ssid = parts[0] if len(parts) > 0 else "<hidden>"
        bssid = parts[1] if len(parts) > 1 else None
    
        if not bssid:
            self.log("Cannot determine BSSID from selection")
            self.capture_btn.config(state=tk.NORMAL)
            return
    
        # TODO: Lấy channel từ scan nếu bạn có map BSSID->channel
        # Hiện tại tạm đặt mặc định 6
        channel = "6"
    
        # File save dialog
        default_name = f"handshake_{ssid}.cap"
        path = filedialog.asksaveasfilename(
            title="Save handshake as",
            defaultextension=".cap",
            initialfile=default_name,
            filetypes=[("Capture files", "*.cap"), ("All files", "*.*")]
        )
        if not path:
            self.log("Handshake capture cancelled by user")
            self.capture_btn.config(state=tk.NORMAL)
            return
    
        # Xác định interface monitor
        iface = self.iface_var.get().strip()
        if not iface:
            self.log("No interface selected")
            self.capture_btn.config(state=tk.NORMAL)
            return
    
        # Thử chuyển sang monitor mode
        try:
            self.log(f"Enabling monitor mode on {iface}...")
            subprocess.run(["sudo", "airmon-ng", "start", iface], check=True)
            monitor_iface = iface + "mon"
            self.log(f"Monitor interface: {monitor_iface}")
        except Exception as e:
            self.log(f"Failed to enable monitor mode: {e}")
            self.capture_btn.config(state=tk.NORMAL)
            return
    
        # Chạy airodump-ng
        cmd = ["sudo", "airodump-ng", "--bssid", bssid, "-c", channel, "-w", path, monitor_iface]
        self.log(f"Running: {' '.join(cmd)}")
    
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
            def stream(pipe, name):
                for line in iter(pipe.readline, ""):
                    if not line:
                        break
                    self.after(0, lambda l=line.rstrip(): self.log(f"{name}: {l}"))
                pipe.close()
    
            t_out = threading.Thread(target=stream, args=(proc.stdout, "OUT"))
            t_err = threading.Thread(target=stream, args=(proc.stderr, "ERR"))
            t_out.start()
            t_err.start()
    
            proc.wait()
            t_out.join()
            t_err.join()
    
            # airodump-ng thường tự tạo file: <path>-01.cap
            captured_file = path + "-01.cap"
            if os.path.exists(captured_file):
                self.last_capture_path = captured_file
                self.log(f"Handshake capture saved to: {captured_file}")
            else:
                self.log("Capture file not found, maybe no handshake captured")
    
        except Exception as e:
            self.log(f"Failed to run airodump-ng: {e}")
    
        # Quay về chế độ managed (tùy chọn)
        try:
            subprocess.run(["sudo", "airmon-ng", "stop", monitor_iface], check=False)
        except:
            pass
        
        self.capture_btn.config(state=tk.NORMAL)
    

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

        # try to see if aircrack-ng is available; if not simulate
        try:
            proc = shutil.which("aircrack-ng")
        except Exception:
            proc = None

        if proc:
            self.log("aircrack-ng found, running real command (will prompt for .cap and wordlist if needed)")
            self.log(f"aircrack-ng path: {proc}")

            # Ensure we have a capture file
            cap = self.last_capture_path
            if not cap or not os.path.exists(cap):
                cap = filedialog.askopenfilename(title="Select capture file (.cap)", filetypes=[("Capture files", "*.cap"), ("All files", "*.*")])
                if not cap:
                    self.log("No capture file provided. Aborting real crack.")
                    self.crack_btn.config(state=tk.NORMAL)
                    return

            # Ensure we have a wordlist
            wordlist = self.wordlist_var.get().strip()
            if not wordlist or not os.path.exists(wordlist):
                wordlist = filedialog.askopenfilename(title="Select wordlist file", filetypes=[("Wordlist", "*.*")])
                if not wordlist:
                    self.log("No wordlist provided. Aborting real crack.")
                    self.crack_btn.config(state=tk.NORMAL)
                    return

            # Run aircrack-ng -w <wordlist> <capture>
            try:
                exe = proc
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
                self.log(f"aircrack-ng exited with code: {code}")
            except Exception as e:
                self.log(f"Failed to run aircrack-ng: {e}")
            time.sleep(0.2)
        else:
            # simulated cracking progress
            steps = 6
            for i in range(steps):
                time.sleep(0.9)
                self.log(f"Cracking... {int((i+1)/steps*100)}%")

            # random outcome
            if random.random() < 0.35:
                key = "correcthorsebatterystaple"
                self.log(f"Key found: {key}")
                messagebox.showinfo("Crack result", f"Key found: {key}")
            else:
                self.log("Key not found (simulated)")
                messagebox.showinfo("Crack result", "Key not found (simulated)")

        self.crack_btn.config(state=tk.NORMAL)

    def save_output(self):
        txt = self.output.get("1.0", tk.END)
        if not txt.strip():
            messagebox.showinfo("No output", "There is no terminal output to save.")
            return
        path = filedialog.asksaveasfilename(title="Save output", defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(txt)
        self.log(f"Output saved to: {path}")


if __name__ == '__main__':
    app = DesktopApp()
    app.mainloop()
