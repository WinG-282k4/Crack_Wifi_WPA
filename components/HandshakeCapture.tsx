
import React from 'react';
import type { Network } from '../types';

interface HandshakeCaptureProps {
  targetNetwork: Network;
  handshakeCaptured: boolean;
  isLoading: boolean;
}

const HandshakeCapture: React.FC<HandshakeCaptureProps> = ({
  targetNetwork,
  handshakeCaptured,
  isLoading,
}) => {
  return (
    <div>
      <h2 className="text-2xl font-bold text-green-400 mb-2">Step 3: Capture WPA Handshake</h2>
      <p className="text-gray-400 mb-4">
        Targeting: <span className="text-green-300 font-bold">{targetNetwork.essid}</span> ({targetNetwork.bssid})
      </p>

      <div className="bg-gray-900 p-4 rounded-lg border border-gray-700 mb-6">
        <div className="flex justify-between items-center">
          <span className="font-semibold text-gray-300">Handshake Status:</span>
          {handshakeCaptured ? (
            <span className="px-3 py-1 rounded-full bg-green-500 text-white text-sm font-bold">CAPTURED</span>
          ) : (
            <span className="px-3 py-1 rounded-full bg-yellow-500 text-black text-sm font-bold animate-pulse">
              {isLoading ? 'CAPTURING...' : 'PENDING'}
            </span>
          )}
        </div>
      </div>
      
      {isLoading && !handshakeCaptured && (
        <div className="mt-4 text-center">
          <p className="text-gray-400">Attempting to capture handshake automatically...</p>
          <p className="text-gray-500 text-sm">This may involve forcing a client to reconnect.</p>
        </div>
      )}
    </div>
  );
};

export default HandshakeCapture;
