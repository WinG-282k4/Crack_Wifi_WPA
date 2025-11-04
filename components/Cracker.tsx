
import React from 'react';

interface CrackerProps {
  isLoading: boolean;
}

const Cracker: React.FC<CrackerProps> = ({ isLoading }) => {
  return (
    <div>
      <h2 className="text-2xl font-bold text-green-400 mb-4">Step 4: Offline Password Cracking</h2>
      <p className="text-gray-400 mb-6">
        With the WPA handshake captured, we are now attempting to crack the password offline using a default wordlist (rockyou.txt).
      </p>

      {isLoading && (
        <div className="flex items-center space-x-4">
          <svg className="animate-spin h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <span className="text-lg text-yellow-400 animate-pulse">Cracking in progress...</span>
        </div>
      )}
    </div>
  );
};

export default Cracker;
