
import React from 'react';
import type { Network } from '../types';
import Button from './Button';

interface NetworkScannerProps {
  monitorInterface: string;
  networks: Network[];
  isLoading: boolean;
  onScan: () => void;
  onSelectNetwork: (network: Network) => void;
}

const NetworkScanner: React.FC<NetworkScannerProps> = ({
  monitorInterface,
  networks,
  isLoading,
  onScan,
  onSelectNetwork,
}) => {
  return (
    <div>
      <h2 className="text-2xl font-bold text-green-400 mb-4">Step 2: Scan for Networks</h2>
      <p className="text-gray-400 mb-6">
        Using <span className="text-green-300 font-semibold">{monitorInterface}</span>. Click scan to discover nearby wireless networks. Select a target network to proceed.
      </p>

      <Button onClick={onScan} isLoading={isLoading} disabled={isLoading}>
        Scan for Networks
      </Button>

      <div className="mt-6 overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr>
              <th className="p-2 border-b border-gray-600">BSSID</th>
              <th className="p-2 border-b border-gray-600">CH</th>
              <th className="p-2 border-b border-gray-600">PWR</th>
              <th className="p-2 border-b border-gray-600">ESSID</th>
              <th className="p-2 border-b border-gray-600">Action</th>
            </tr>
          </thead>
          <tbody>
            {networks.length > 0 ? networks.map(net => (
              <tr key={net.bssid} className="hover:bg-gray-700/50">
                <td className="p-2 border-b border-gray-700">{net.bssid}</td>
                <td className="p-2 border-b border-gray-700">{net.channel}</td>
                <td className="p-2 border-b border-gray-700">{net.power}</td>
                <td className="p-2 border-b border-gray-700 text-green-300">{net.essid}</td>
                <td className="p-2 border-b border-gray-700">
                  <Button variant="secondary" onClick={() => onSelectNetwork(net)} className="py-1 px-2 text-sm">
                    Select
                  </Button>
                </td>
              </tr>
            )) : (
              <tr>
                <td colSpan={5} className="p-4 text-center text-gray-500">
                  {isLoading ? 'Scanning...' : 'No networks found yet. Click "Scan for Networks" to begin.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default NetworkScanner;
