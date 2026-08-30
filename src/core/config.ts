import { SOC2Control } from '../types/policy.js';

export const DEFAULT_CONTROLS: SOC2Control[] = [
  {
    id: 'CC6.1',
    category: 'SECURITY',
    title: 'Logical Access Security',
    description: 'The entity implements logical access security software, infrastructure, and architectures.',
    tscReference: 'CC6.1',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC6.6',
    category: 'SECURITY',
    title: 'Encryption in Transit & at Rest',
    description: 'The entity implements logical access security measures to protect against threats from sources outside its system boundaries.',
    tscReference: 'CC6.6',
    severity: 'CRITICAL',
    isAutomated: true,
  },
  {
    id: 'CC6.7',
    category: 'SECURITY',
    title: 'Malware Protection',
    description: 'The entity prevents or detects the installation of unauthorized software.',
    tscReference: 'CC6.7',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC6.8',
    category: 'SECURITY',
    title: 'Code Change Protection & Reviews',
    description: 'The entity prevents unauthorized code modifications via branch enforcement and peer reviews.',
    tscReference: 'CC6.8',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC7.2',
    category: 'SECURITY',
    title: 'System Monitoring & Anomaly Detection',
    description: 'The entity monitors infrastructure to detect anomalies and unauthorized actions.',
    tscReference: 'CC7.2',
    severity: 'CRITICAL',
    isAutomated: true,
  },
];
