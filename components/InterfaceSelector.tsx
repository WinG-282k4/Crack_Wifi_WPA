
import React from 'react';
import Button from './Button';

interface InterfaceSelectorProps {
  interfaces: string[];
  selectedInterface: string | null;
  setSelectedInterface: (iface: string) => void;
  isLoading: boolean;
  onStartMonitorMode: () => void;
}

const InterfaceSelector: React.FC<InterfaceSelectorProps> = ({
  interfaces,
  selectedInterface,
  setSelectedInterface,
  isLoading,
  onStartMonitorMode,
}) => {
  return (
    <div>
      <h2 className="text-2xl font-bold text-green-400 mb-4">Step 1: Select Network Interface</h2>
      <p className="text-gray-400 mb-6">Choose a wireless interface to put into monitor mode. This is a required first step to begin scanning.</p>
      
      {interfaces.length > 0 ? (
        <div className="space-y-2 mb-6">
          {interfaces.map(iface => (
            <label
              key={iface}
              className={`block p-3 rounded-md border transition-colors cursor-pointer ${
                selectedInterface === iface 
                  ? 'bg-green-900/50 border-green-500' 
                  : 'bg-gray-700/50 border-gray-600 hover:bg-gray-700'
              }`}
            >
              <input
                type="radio"
                name="interface"
                value={iface}
                checked={selectedInterface === iface}
                onChange={() => setSelectedInterface(iface)}
                className="hidden"
              />
              <span className="font-semibold">{iface}</span>
            </label>
          ))}
        </div>
      ) : (
        <div className="text-center text-gray-500 mb-6">
          <p>Searching for wireless interfaces...</p>
        </div>
      )}

      <Button
        onClick={onStartMonitorMode}
        disabled={!selectedInterface}
        isLoading={isLoading}
      >
        Start Monitor Mode
      </Button>
    </div>
  );
};

export default InterfaceSelector;
