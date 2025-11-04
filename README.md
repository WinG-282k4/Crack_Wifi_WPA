<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/drive/17arglK56nt9xQ2zkCvOIq-FBCtxLI2MW

## Run Locally

**Prerequisites:** Node.js

1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Running on Kali Linux (real wireless tools)

This project ships a small local command server that will run a whitelist of system commands (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng, iwlist, iwconfig, etc.). This keeps the front-end browser code safe while letting you invoke privileged wireless tools from a browser UI on a trusted, local machine.

Steps:

1. Install dependencies:

```bash
npm install
```

2. Start the command server (run this in a terminal on your Kali machine; you may need sudo to run wireless tools):

```bash
npm run start-server
# You may need to run with sudo if the tools require root privileges
```

3. In a separate terminal, start the Vite dev server:

```bash
npm run dev
```

4. Open the app at http://localhost:5173 (or the URL Vite prints).

5. To make the app use the real command server, set the environment variable `VITE_COMMAND_SERVER_URL` (or `VITE_USE_REAL=true`) when running Vite. Example on Linux:

```bash
VITE_COMMAND_SERVER_URL=http://localhost:4000 npm run dev
# or
VITE_USE_REAL=true npm run dev

Alternatively you can use the included cross-platform npm script which sets these for you:

```bash
# start server in one terminal (may need sudo)
npm run start-server

# then in another terminal start Vite in "real" mode (cross-platform)
npm run dev:real
```
```

Security note: The server uses a strict whitelist. Only run the server locally on a trusted machine. Do not expose it to untrusted networks.
