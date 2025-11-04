
import React from 'react';
import type { Network } from '../types';
import Button from './Button';

interface ResultsProps {
  targetNetwork: Network;
  crackedPassword: string;
  onReset: () => void;
}

const Results: React.FC<ResultsProps> = ({ targetNetwork, crackedPassword, onReset }) => {
  return (
    <div>
      <h2 className="text-2xl font-bold text-green-400 mb-4">Step 5: Results</h2>
      <p className="text-gray-400 mb-6">The dictionary attack was successful.</p>

      <div className="bg-gray-900 border border-green-500 rounded-lg p-6 text-center">
        <p className="text-gray-300 text-lg">Password for <span className="font-bold text-white">{targetNetwork.essid}</span> is:</p>
        <p className="text-3xl font-bold text-green-400 my-4 bg-gray-800 p-4 rounded-md">
          {crackedPassword}
        </p>
      </div>

      <div className="mt-8 text-center">
        <h3 className="text-xl font-bold text-green-400 mb-4">Simulation Complete</h3>
        <p className="text-gray-400 mb-6">You have successfully completed the Wi-Fi security audit simulation.</p>
        <Button onClick={onReset} variant="secondary">
          Run Simulation Again
        </Button>
      </div>
    </div>
  );
};

export default Results;
