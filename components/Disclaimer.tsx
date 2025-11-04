
import React from 'react';

const Disclaimer: React.FC = () => {
  return (
    <div className="bg-yellow-900/50 border border-yellow-700 text-yellow-200 px-4 py-3 rounded-lg relative mb-8" role="alert">
      <strong className="font-bold">Disclaimer: </strong>
      <span className="block sm:inline">
        This is a UI simulation for educational purposes ONLY. No real network commands are executed.
      </span>
    </div>
  );
};

export default Disclaimer;
