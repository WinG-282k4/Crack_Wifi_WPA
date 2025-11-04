
import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
}

const Card: React.FC<CardProps> = ({ children, className }) => {
  return (
    <div className={`bg-gray-800 border border-gray-700 rounded-lg shadow-lg p-6 ${className}`}>
      {children}
    </div>
  );
};

export default Card;
