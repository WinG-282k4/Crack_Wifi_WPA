
import type { Network, Client } from '../types';

const MOCK_NETWORKS: Network[] = [
    { bssid: '00:1A:2B:3C:4D:5E', channel: 1, essid: 'HomeNetwork_2.4GHz', power: -45, beacons: 120, data: 5, encryption: 'WPA2' },
    { bssid: '58:D3:12:1E:9A:8C', channel: 6, essid: 'CoffeeShop_FreeWiFi', power: -62, beacons: 88, data: 12, encryption: 'WPA2' },
    { bssid: 'AA:BB:CC:DD:EE:FF', channel: 11, essid: 'CorpGuest', power: -75, beacons: 45, data: 0, encryption: 'WPA2' },
    { bssid: '12:34:56:78:90:AB', channel: 44, essid: 'MySecureNet_5GHz', power: -50, beacons: 250, data: 30, encryption: 'WPA2' },
    { bssid: 'DE:AD:BE:EF:CA:FE', channel: 1, essid: '<hidden>', power: -80, beacons: 10, data: 0, encryption: 'WPA2' },
];

const MOCK_CLIENTS: { [key: string]: Client[] } = {
    '00:1A:2B:3C:4D:5E': [{ mac: 'F0:E1:D2:C3:B4:A5', bssid: '00:1A:2B:3C:4D:5E', power: -55, frames: 150 }],
    '58:D3:12:1E:9A:8C': [
        { mac: 'C0:FF:EE:A1:B2:C3', bssid: '58:D3:12:1E:9A:8C', power: -65, frames: 320 },
        { mac: '98:76:54:32:10:FE', bssid: '58:D3:12:1E:9A:8C', power: -70, frames: 95 }
    ],
    'AA:BB:CC:DD:EE:FF': [],
    '12:34:56:78:90:AB': [{ mac: 'AB:CD:EF:12:34:56', bssid: '12:34:56:78:90:AB', power: -52, frames: 800 }],
    'DE:AD:BE:EF:CA:FE': [],
};


const delay = (ms: number) => new Promise(res => setTimeout(res, ms));

const simulationService = {
  getNetworkInterfaces: async () => {
    // Real command would be something like `iwconfig` or `ifconfig` and parsing the output.
    await delay(500);
    return {
      interfaces: ['wlan0', 'wlan1'],
      output: `[system] Found 2 wireless interfaces. Ready for selection.`
    };
  },

  startMonitorMode: async (iface: string) => {
    // Command: sudo airmon-ng start ${iface}
    await delay(1500);
    const monitorInterface = `${iface}mon`;
    return {
      monitorInterface,
      output: [
        `$ sudo airmon-ng start ${iface}`,
        `Monitoring mode enabled on ${monitorInterface}`
      ]
    };
  },

  scanForNetworks: async (monitorIface: string, onData: (networks: Network[], output: string[]) => void) => {
    // Command: sudo airodump-ng ${monitorIface}
    onData([], [`$ sudo airodump-ng ${monitorIface}`]);
    await delay(1000);
    for (let i = 0; i < MOCK_NETWORKS.length; i++) {
        await delay(800 + Math.random() * 500);
        const network = MOCK_NETWORKS[i];
        const output = `[airodump] Discovered: ${network.essid.padEnd(20)} ${network.bssid}  CH: ${network.channel.toString().padStart(2, ' ')}  PWR: ${network.power}`;
        onData([network], [output]);
    }
  },

  getMockClients: (bssid: string): Client[] => {
    return MOCK_CLIENTS[bssid] || [];
  },

  captureHandshake: async (network: Network) => {
    const monitorIface = 'wlan0mon'; // Assuming a monitor interface name for the command
    // Command: sudo airodump-ng --bssid ${network.bssid} -c ${network.channel} --write handshake_capture ${monitorIface}
    await delay(3000);
    const hasClient = MOCK_CLIENTS[network.bssid]?.length > 0;
    const output = [
      `$ sudo airodump-ng --bssid ${network.bssid} -c ${network.channel} --write handshake_capture ${monitorIface}`,
      `[airodump] Listening on channel ${network.channel}...`,
    ];

    if (!hasClient) {
        output.push(`[airodump] No clients detected for ${network.essid}. Waiting for a device to connect to capture handshake...`);
        return { captured: false, output };
    }
    
    // Simulate natural handshake capture for networks with clients
    if(Math.random() > 0.6) {
        await delay(4000);
        output.push(`[airodump] WPA handshake: ${network.bssid}`);
        return { captured: true, output };
    }

    output.push('[airodump] No handshake captured yet. You can try forcing a deauthentication if a client is connected.');
    return { captured: false, output };
  },

  forceHandshake: async (network: Network, client: Client, monitorIface: string) => {
    // Command: sudo aireplay-ng --deauth 5 -a ${network.bssid} -c ${client.mac} ${monitorIface}
    await delay(2000);
    return {
      output: [
        `$ sudo aireplay-ng --deauth 5 -a ${network.bssid} -c ${client.mac} ${monitorIface}`,
        `[aireplay-ng] Sending 5 deauth packets to ${client.mac}...`,
        `[aireplay-ng] Client disconnected. Reconnecting...`,
        `[airodump] WPA handshake: ${network.bssid}`
      ]
    };
  },

  crackPassword: async (network: Network, wordlist: string) => {
    // Command: aircrack-ng -w /path/to/${wordlist} -b ${network.bssid} handshake_capture-01.cap
    const output: string[] = [
        `$ aircrack-ng -w /path/to/${wordlist} -b ${network.bssid} handshake_capture-01.cap`,
        '[aircrack-ng] Initializing... aircrack-ng 1.7',
        '[aircrack-ng] Reading packets, please wait...',
    ];
    
    for (let i = 0; i <= 100; i += (10 + Math.random()*15)) {
        await delay(400);
        output.push(`[aircrack-ng] ${Math.round(i)}% tested. Trying keys: ${Math.floor(Math.random() * 100000)}...`);
    }

    const password = 'password123'; // The "found" password
    
    output.push(`[aircrack-ng] KEY FOUND! [ ${password} ]`);

    return {
      password,
      output
    };
  }
};

export { simulationService };
