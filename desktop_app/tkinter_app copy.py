#!/usr/bin/env python3
"""
Wi-Fi Security Tool (Kali Linux Edition)
- Hiển thị mạng Wi-Fi phát hiện được (có CH)
- Bắt handshake tự động cho đến khi có WPA handshake
- Crack bằng aircrack-ng (hoặc mô phỏng nếu không có)
- GUI bằng Tkinter
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import datetime
import os
import subprocess
import shutil
import random
import re
from typing import List

APP_TITLE = "Wi-Fi Security Tool (Kali Edition)"


class DesktopApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("960x560")

        self.nets_info = {}  # Lưu (BSSID -> {ssid, channel, signal})
        self.last_capture_path = None
        self._build_ui()
        self.populate_interfaces()

    def _build_ui(self):
        left = ttk.Frame(self)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=8)

        ttk.Label(left, text="Detected networks (SSID | BSSID | CH | Signal)").pack(anchor=tk.W)

        # Interface selector
        ttk.Label(left, text="Interface:").pack(anchor=tk.W, pady=(6, 0))
        iface_frame = ttk.Frame(left)
        iface_frame.pack(fill=tk.X)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(iface_frame, textvariable=self.iface_var, values=[])
        self.iface_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(iface_frame, text="Refresh", command=self.populate_interfaces).pack(side=tk.LEFT, padx=(5, 0))

        # Network list
        self.net_listbox = tk.Listbox(left, width=38, height=18)
        self.net_listbox.pack(pady=6)

        # Buttons
        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill=tk.X, pady=6)
        ttk.Button(btn_frame, text="Scan", command=self.start_scan).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(btn_frame, text="Capture Handshake", command=self.start_capture).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(left, text="Crack (simulate/real)", command=self.start_crack).pack(fill=tk.X)

        ttk.Label(left, text="Wordlist:").pack(anchor=tk.W, pady=(8, 0))
        wl_frame = ttk.Frame(left)
        wl_frame.pack(fill=tk.X)
        self.wordlist_var = tk.StringVar()
        ttk.Entry(wl_frame, textvariable=self.wordlist_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(wl_frame, text="Browse", command=self.select_wordlist).pack(side=tk.LEFT, padx=(5, 0))

        ttk.Button(left, text="Save Output...", command=self.save_output).pack(fill=tk.X, pady=(10, 0))

        # Terminal output
        right = ttk.Frame(self)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=8, pady=8)
        ttk.Label(right, text="Terminal Output").pack(anchor=tk.W)
        self.output = tk.Text(right, wrap="word")
        self.output.pack(fill=tk.BOTH, expand=True)

        self.log("App started")

    # Utility --------------------------------------------------
    def log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.output.insert(tk.END, f"[{ts}] {msg}\n")
        self.output.see(tk.END)

    def populate_interfaces(self):
        try:
            out = subprocess.check_output(["iwconfig"], text=True, stderr=subprocess.DEVNULL)
            interfaces = [line.split()[0] for line in out.splitlines() if line and not line.startswith(" ")]
        except Exception:
            interfaces = []
        if not interfaces:
            interfaces = os.listdir("/sys/class/net")
        self.iface_combo["values"] = interfaces
        if interfaces:
            self.iface_var.set(interfaces[0])
        self.log(f"Interfaces: {', '.join(interfaces)}")

    def select_wordlist(self):
        p = filedialog.askopenfilename(title="Select Wordlist", filetypes=[("Wordlist", "*.*")])
        if p:
            self.wordlist_var.set(p)
            self.log(f"Wordlist selected: {p}")

    # Scan networks ---------------------------------------------
    def start_scan(self):
        threading.Thread(target=self._scan, daemon=True).start()

    def _scan(self):
        iface = self.iface_var.get().strip()
        if not iface:
            self.log("No interface selected for scan.")
            return

        self.net_listbox.delete(0, tk.END)
        self.log(f"Scanning networks on {iface}...")

        cmd = ["sudo", "iwlist", iface, "scan"]
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=12)
        except subprocess.CalledProcessError as e:
            out = e.output
        except Exception as e:
            self.log(f"Scan failed: {e}")
            return

        cells = out.split("Cell ")
        nets = []
        for c in cells[1:]:
            bssid_m = re.search(r"Address: ([0-9A-Fa-f:]{17})", c)
            ssid_m = re.search(r'ESSID:"(.*)"', c)
            ch_m = re.search(r"Channel:(\d+)", c)
            sig_m = re.search(r"Signal level=([-0-9]+)\s*dBm", c)
            if bssid_m:
                bssid = bssid_m.group(1)
                ssid = ssid_m.group(1) if ssid_m else "<hidden>"
                ch = ch_m.group(1) if ch_m else "?"
                sig = sig_m.group(1) if sig_m else ""
                nets.append((ssid, bssid, ch, sig))
                self.nets_info[bssid] = {"ssid": ssid, "channel": ch, "signal": sig}

        if not nets:
            self.log("No networks found. (Try enabling interface in monitor mode first)")
            return

        for ssid, bssid, ch, sig in nets:
            display = f"{ssid} | {bssid} | CH {ch} | {sig} dBm"
            self.net_listbox.insert(tk.END, display)

        self.log(f"Scan complete: {len(nets)} networks found.")

    # Capture handshake -----------------------------------------
    def start_capture(self):
        sel = self.net_listbox.curselection()
        if not sel:
            messagebox.showinfo("Select Network", "Please select a network first.")
            return
        idx = sel[0]
        entry = self.net_listbox.get(idx)
        bssid = re.search(r"([0-9A-Fa-f:]{17})", entry)
        if not bssid:
            self.log("Invalid selection.")
            return
        bssid = bssid.group(1)
        threading.Thread(target=self._capture, args=(bssid,), daemon=True).start()

    def _capture(self, bssid):
        iface = self.iface_var.get().strip()
        if not iface:
            self.log("No interface selected.")
            return

        ssid = self.nets_info.get(bssid, {}).get("ssid", "unknown")
        ch = self.nets_info.get(bssid, {}).get("channel", "6")

        self.log(f"Starting handshake capture on {ssid} ({bssid}) channel {ch}...")

        try:
            subprocess.run(["sudo", "airmon-ng", "start", iface], check=True)
            mon = iface + "mon"
        except Exception as e:
            self.log(f"Failed to enable monitor mode: {e}")
            return

        cap_name = f"/home/kali/Desktop/handshake_{ssid.replace(' ', '_')}.cap"
        cmd = ["sudo", "airodump-ng", "--bssid", bssid, "-c", ch, "-w", cap_name, mon]

        self.log(f"Running: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        found_handshake = False
        start_time = time.time()

        for line in iter(proc.stdout.readline, ""):
            if "WPA handshake" in line:
                found_handshake = True
                self.log("✅ WPA handshake detected!")
                break
            if time.time() - start_time > 60:
                break

        proc.terminate()
        time.sleep(1)

        cap_file = cap_name + "-01.cap"
        if found_handshake and os.path.exists(cap_file):
            self.last_capture_path = cap_file
            self.log(f"Handshake saved to: {cap_file}")
        else:
            self.log("❌ No handshake captured. Try again with target active client.")

        subprocess.run(["sudo", "airmon-ng", "stop", mon], check=False)

    # Crack handshake -------------------------------------------
    def start_crack(self):
        threading.Thread(target=self._crack, daemon=True).start()

    def _crack(self):
        self.log("Starting cracking routine...")
        aircrack = shutil.which("aircrack-ng")
        if not aircrack:
            self.log("aircrack-ng not found. Simulating crack...")
            for i in range(5):
                time.sleep(1)
                self.log(f"Cracking... {20*(i+1)}%")
            if random.random() < 0.3:
                key = "correcthorsebatterystaple"
                self.log(f"Key found: {key}")
            else:
                self.log("Key not found (simulated).")
            return

        cap = self.last_capture_path
        if not cap or not os.path.exists(cap):
            cap = filedialog.askopenfilename(title="Select capture file", filetypes=[("cap files", "*.cap")])
            if not cap:
                self.log("No capture file provided.")
                return

        wordlist = self.wordlist_var.get().strip()
        if not wordlist or not os.path.exists(wordlist):
            wordlist = filedialog.askopenfilename(title="Select wordlist", filetypes=[("Wordlist", "*.*")])
            if not wordlist:
                self.log("No wordlist provided.")
                return

        cmd = [aircrack, "-w", wordlist, cap]
        self.log(f"Running: {' '.join(cmd)}")

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in iter(proc.stdout.readline, ""):
            self.after(0, lambda l=line.rstrip(): self.log(l))
        proc.wait()
        self.log(f"aircrack-ng exited with code {proc.returncode}")

    # Save output ------------------------------------------------
    def save_output(self):
        txt = self.output.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showinfo("No Output", "Nothing to save.")
            return
        path = filedialog.asksaveasfilename(title="Save Log", defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt)
            self.log(f"Output saved to: {path}")


if __name__ == "__main__":
    app = DesktopApp()
    app.mainloop()
