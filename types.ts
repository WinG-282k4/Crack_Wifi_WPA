
export type Step =
  | 'SELECT_INTERFACE'
  | 'SCANNING'
  | 'CAPTURING'
  | 'CRACKING'
  | 'DONE';

export interface Network {
  bssid: string;
  channel: number;
  essid: string;
  power: number;
  beacons: number;
  data: number;
  encryption: string;
}

export interface Client {
    mac: string;
    bssid: string;
    power: number;
    frames: number;
}
