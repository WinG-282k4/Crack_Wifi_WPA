# Crack_Wifi_WPA

A practical desktop toolkit for scanning Wi‑Fi networks, capturing WPA/WPA2 handshakes, and attempting password cracking using wordlists. This repository focuses on a Python desktop app and helper scripts — there is no web app.

## Structure

- `desktop_app/`
  - Tkinter app (main entry: `tkinter_app copy.py`) and additional examples.
  - Other files: `Crack_WPA.py`, `app(main).py`, `app_backup.py`, `README.md`, `requirements.txt`.
- `tool/`
  - Helper scripts and sample artifacts:
    - `wpa_crack.py`, `wpa2_crack_main.py`, `wpa2_crack_multimain.py`, `wpa2_keys.py`
    - Example outputs and captures: `cracked_wifi.txt`, `dump-01.cap`, `test.txt`

## Requirements

- Python 3.9+ (Tkinter included in standard Python).
- Optional: PyQt5 if you plan to run the PyQt demo.
- For real capture/crack (Linux recommended): `aircrack-ng` suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`) available in PATH. Monitor mode and appropriate drivers are required.

Install optional dependencies (PyQt5):

```powershell
python -m pip install -r desktop_app/requirements.txt
```

## Quick Start (Tkinter)

Run the desktop app:

```powershell
python "desktop_app/tkinter_app copy.py"
```

Behavior:

- On capture start, a per-network folder is created under `./captures/`:
  - `capture_{SSID_sanitized}_{YYYYMMDD_HHMMSS}` (e.g., `capture_MyWifi_20251217_153012`)
- `airodump-ng` writes files with the prefix `dump` (e.g., `dump-01.cap`) inside that folder.
- After a "WPA handshake" is detected in process output, the app locates the capture file (retrying briefly) and sets `last_capture_path`. A Save‑As dialog appears (defaulting to the capture folder). If you cancel, the file remains in the folder.
- Cracking uses `aircrack-ng` if present; otherwise the app simulates. The final result and elapsed time are shown.

See details in [desktop_app/README.md](desktop_app/README.md).

## Tool Scripts

The `tool/` folder contains example scripts and artifacts for WPA/WPA2 cracking workflows. These are provided as references and may require adaptation for your environment.

Typical usage patterns (adjust as needed):

```powershell
# Explore script usage (if implemented)
python tool/wpa_crack.py --help

# Example: run a cracker with a capture and wordlist (script-specific)
python tool/wpa_crack.py .\tool\dump-01.cap .\wordlists\rockyou.txt
```

If a script does not implement `--help`, open the file to review expected arguments and flow. Some scripts may be prototypes (e.g., multi-main variants) and require editing.

## Notes

- Real wireless operations often require elevated privileges and appropriate wireless hardware/driver support, especially for monitor mode and injection.
- On Windows, consider using WSL or a Linux VM if you need the full `aircrack-ng` toolchain.
- Always use these tools responsibly and only on networks you have permission to test.
