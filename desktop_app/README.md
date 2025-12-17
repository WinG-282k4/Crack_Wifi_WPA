# Desktop App (Tkinter / PyQt5)

This folder contains desktop GUI examples for scanning networks, capturing WPA handshakes, and cracking (real or simulated). The Tkinter version is lightweight and ships with Python; the PyQt5 version requires installing PyQt5.

## Files

- `tkinter_app copy.py` — Tkinter app (current development entry). If you prefer a cleaner name, you can rename it to `tkinter_app.py`.
- `pyqt_app.py` — minimal PyQt5 app (optional).

## Requirements

- Tkinter is included with standard Python on Windows/macOS/Linux.
- PyQt5 is only needed if you want to run `pyqt_app.py`:

```powershell
python -m pip install -r requirements.txt
```

For real capture/cracking (Linux recommended):

- `aircrack-ng` suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`) available in PATH.
- On Windows, consider using WSL or a Linux VM; the app still runs, but the real wireless tools may not be available.

## Run

Run the Tkinter app:

```powershell
python "desktop_app/tkinter_app copy.py"
```

Run the PyQt5 app (optional):

```powershell
python "desktop_app/pyqt_app.py"
```

## Capture Behavior

- When starting a capture, the app creates a per-network folder:
  - `./captures/capture_{SSID_sanitized}_{YYYYMMDD_HHMMSS}`
  - Example: `./captures/capture_MyWifi_20251217_153012`
- Airodump-ng writes files inside that folder with the prefix `dump` (e.g. `dump-01.cap`).
- After a "WPA handshake" is detected in airodump output, the app retries discovery for a short window to locate the `.cap/.pcap/.pcapng` file and sets `last_capture_path`.
- A Save-As dialog will appear (defaulting to the capture folder). If you cancel, the file stays in the capture folder and `last_capture_path` points to it.

## Cracking

- If `aircrack-ng` is found in PATH, the app runs a real crack with your selected wordlist; otherwise it simulates cracking.
- Progress is streamed to the UI. When finished, the app shows a result dialog with the outcome and elapsed time.

## Troubleshooting

- If the app logs a handshake but can't find the `.cap`, check the capture folder under `./captures/` for `dump-01.cap` and confirm it has non-zero size.
- Some environments render `airodump-ng` output in a curses-like UI; the app relies on the process output and the capture files. Ensure airodump is writing files (`-w prefix`) and that you have sufficient permissions (monitor mode enabled).
- On Windows, use WSL or Linux for full support of `aircrack-ng` tools.

## Notes

- These examples are intentionally minimal. Real wireless operations may require elevated privileges and proper drivers.
- Feel free to request additional features (auto-save captures, auto-crack after capture, etc.).
