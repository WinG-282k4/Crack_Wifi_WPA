# Desktop app examples (Tkinter and PyQt5)

This folder contains two simple desktop GUI examples that mirror a subset of the functionality from the web app (network scan, handshake capture, cracking simulation, and terminal output):

- `tkinter_app.py` — a lightweight Tkinter app (recommended for quick testing; ships with standard Python).
- `pyqt_app.py` — a minimal PyQt5 example (requires installing PyQt5; included as an alternative UI).

## Requirements

Install dependencies (PyQt5 is only needed if you want to run `pyqt_app.py`):

```powershell
python -m pip install -r requirements.txt
```

## Run

To run the Tkinter app (no extra dependencies):

```powershell
python "desktop_app/tkinter_app.py"
```

To run the PyQt5 app:

```powershell
python "desktop_app/pyqt_app.py"
```

## Notes

- These examples simulate behavior. If you have `aircrack-ng` installed and available in PATH, the Tkinter app's "Crack" will try to call it; otherwise it performs a simulated cracking routine.
- Use these as starting points — they intentionally avoid privileged system calls and real wireless operations for safety and portability.

Feel free to ask me to wire additional features from the web app into these desktop clients.
