
import React, { useRef, useEffect } from 'react';

interface TerminalOutputProps {
  output: string[];
}

const TerminalOutput: React.FC<TerminalOutputProps> = ({ output }) => {
  const endOfTerminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endOfTerminalRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [output]);

  return (
    <div>
        <h3 className="text-lg font-bold text-green-400 mb-2">Simulated Terminal</h3>
        <div className="bg-black text-white p-4 rounded-lg h-64 overflow-y-auto font-mono text-sm border border-gray-700">
        {output.map((line, index) => (
            <div key={index} className="whitespace-pre-wrap">
                <span className="text-green-500 mr-2">{'>'}</span>
                <span>{line}</span>
            </div>
        ))}
        <div ref={endOfTerminalRef} />
        </div>
    </div>
  );
};

export default TerminalOutput;
