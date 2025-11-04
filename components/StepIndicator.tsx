
import React from 'react';
import type { Step } from '../types';
import { STEPS } from '../constants';

interface StepIndicatorProps {
  currentStep: Step;
}

const StepIndicator: React.FC<StepIndicatorProps> = ({ currentStep }) => {
  const currentStepIndex = STEPS.findIndex(s => s.id === currentStep);

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
      <h2 className="text-lg font-bold text-green-400 mb-4">Workflow</h2>
      <ol className="space-y-3">
        {STEPS.map((step, index) => {
          const isCompleted = index < currentStepIndex;
          const isActive = index === currentStepIndex;

          return (
            <li key={step.id} className="flex items-center">
              <span className={`flex items-center justify-center w-6 h-6 rounded-full mr-3 text-sm font-bold shrink-0
                ${isCompleted ? 'bg-green-500 text-white' : ''}
                ${isActive ? 'bg-green-700 text-white ring-2 ring-green-400' : ''}
                ${!isCompleted && !isActive ? 'bg-gray-600 text-gray-300' : ''}
              `}>
                {isCompleted ? '✓' : index + 1}
              </span>
              <span className={`
                ${isActive ? 'text-green-300 font-semibold' : ''}
                ${isCompleted ? 'text-gray-400 line-through' : ''}
                ${!isCompleted && !isActive ? 'text-gray-300' : ''}
              `}>
                {step.name}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
};

export default StepIndicator;
