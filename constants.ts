
import type { Step } from './types';

export const STEPS: { id: Step; name: string }[] = [
  { id: 'SELECT_INTERFACE', name: '1. Select Interface' },
  { id: 'SCANNING', name: '2. Scan for Networks' },
  { id: 'CAPTURING', name: '3. Capture Handshake' },
  { id: 'CRACKING', name: '4. Crack Password' },
  { id: 'DONE', name: '5. Results' },
];
