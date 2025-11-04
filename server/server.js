#!/usr/bin/env node
import { spawn } from "child_process";
import http from "http";

// Simple command execution server for local development on Linux (Kali).
// SECURITY: This server intentionally implements a strict whitelist. Do NOT
// run it exposed to untrusted networks or without reviewing the allowed list.

const PORT = process.env.PORT || 4000;

// Whitelist common tools used by this project. Add entries only if you trust them.
const ALLOWED_COMMANDS = new Set([
  "iwconfig",
  "ifconfig",
  "airmon-ng",
  "airodump-ng",
  "aireplay-ng",
  "aircrack-ng",
  "timeout",
  "ls",
  "pwd",
  "whoami",
]);

function isAllowed(command) {
  // Only allow the base command (no paths). This is intentionally strict.
  const base = command.split("/").pop();
  return ALLOWED_COMMANDS.has(base);
}

const server = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/run") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        const parsed = JSON.parse(body || "{}");
        const command = parsed.command;
        const args = Array.isArray(parsed.args) ? parsed.args : [];

        if (!command) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({ error: 'Missing "command" in request body' })
          );
          return;
        }

        if (!isAllowed(command)) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Command not allowed", command }));
          return;
        }

        // Spawn the command directly (no shell) for safety.
        const child = spawn(command, args, {
          stdio: ["ignore", "pipe", "pipe"],
        });

        let stdout = "";
        let stderr = "";

        child.stdout.on("data", (chunk) => {
          stdout += chunk.toString();
        });
        child.stderr.on("data", (chunk) => {
          stderr += chunk.toString();
        });

        child.on("error", (err) => {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: String(err) }));
        });

        child.on("close", (code) => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ command, args, code, stdout, stderr }));
        });
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: String(err) }));
      }
    });

    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Command server listening on http://localhost:${PORT}`);
  // Recommend running as root/sudo if you need to access wireless tools on Kali.
});
