export type CommandResult = {
  command: string;
  args: string[];
  code: number;
  stdout: string;
  stderr: string;
};

// Vite exposes env variables through import.meta.env. Use VITE_COMMAND_SERVER_URL to override.
const SERVER_URL =
  (import.meta as any).env?.VITE_COMMAND_SERVER_URL ||
  "http://localhost:4000/run";

export async function runCommand(
  command: string,
  args: string[] = []
): Promise<CommandResult> {
  const res = await fetch(SERVER_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command, args }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Command server error: ${res.status} ${body}`);
  }

  const json = await res.json();
  return json as CommandResult;
}

export default { runCommand };
