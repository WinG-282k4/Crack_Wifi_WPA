<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# wi-fi-security-tool-simulator — Run locally

This repository contains a browser UI (Vite + React) and a small local command server used to run a whitelist of wireless tools. The front-end is safe to run in a browser; the server exposes a limited, local API for invoking system commands (only on trusted machines).

## Run locally

**Prerequisites:** Node.js (v16+ recommended)

1. Install dependencies:

```bash
npm install
```

2. (Optional) Start the local command server. This server exposes a whitelist of system commands used for "real" wireless tooling. Only run this on a trusted machine.

```bash
# starts server at http://localhost:4000
npm run start-server
# On Linux you may need sudo to access wireless devices
```

3. Start the Vite dev server (open the app at http://localhost:5173):

```bash
npm run dev
```

4. Use the real command server from the front-end

The repo includes a cross-platform script that sets the environment variables required for the front-end to talk to the command server:

```bash
npm run dev:real
```

If you prefer to set environment variables yourself, here are common ways to do that:

- PowerShell (Windows):

```powershell
$env:VITE_COMMAND_SERVER_URL = 'http://localhost:4000'; npm run dev
```

- cmd.exe (Windows):

```cmd
set VITE_COMMAND_SERVER_URL=http://localhost:4000 && npm run dev
```

- macOS / Linux (bash/zsh):

```bash
VITE_COMMAND_SERVER_URL=http://localhost:4000 npm run dev
```

Prefer `npm run dev:real` on Windows to avoid shell-specific environment syntax; that script uses `cross-env` for cross-platform behavior.

## Running on Kali Linux (real wireless tools)

On Kali you can use the server to run actual wireless tools (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng, iwlist, iwconfig, etc.). Steps are the same as above, but you will typically run the server with elevated privileges to access wireless interfaces:

1. Install dependencies:

```bash
npm install
```

2. Start the command server (may need sudo):

```bash
sudo npm run start-server
```

3. In a separate terminal, start the front-end. Use the cross-platform script or set env vars directly:

```bash
npm run dev:real
# or, if you prefer manual env vars:
VITE_COMMAND_SERVER_URL=http://localhost:4000 npm run dev
```

4. Open the app at http://localhost:5173 (or the URL Vite prints).

### Notes

- The command server listens by default on port 4000. If you change that port, update `VITE_COMMAND_SERVER_URL` accordingly.
- `npm run dev:real` uses `cross-env` to set `VITE_USE_REAL=true` and `VITE_COMMAND_SERVER_URL` in a cross-platform way.

Security note: The server enforces a strict command whitelist. Do not expose the server to untrusted networks. Only run the server on machines you control and trust.
