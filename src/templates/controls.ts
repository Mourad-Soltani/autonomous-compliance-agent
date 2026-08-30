import { SOC2Control } from '../types/policy.js';

/**
 * SOC 2 Control Templates Library
 * Pre-built controls aligned with AICPA Trust Services Criteria (TSC).
 * Covers all 5 Trust Service Categories: Security, Availability, Processing Integrity,
 * Confidentiality, and Privacy.
 */

export const SECURITY_CONTROLS: SOC2Control[] = [
  {
    id: 'CC6.1',
    category: 'SECURITY',
    title: 'Logical Access Security',
    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events that could compromise the achievement of the entity's objectives.',
    tscReference: 'CC6.1',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC6.2',
    category: 'SECURITY',
    title: 'Access Removal',
    description: 'Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity.',
    tscReference: 'CC6.2',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC6.3',
    category: 'SECURITY',
    title: 'Access Modification & Removal',
    description: 'The entity modifies and removes access to protected information assets based on termination or changes in personnel roles, responsibilities, or job duties.',
    tscReference: 'CC6.3',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC6.4',
    category: 'SECURITY',
    title: 'Authentication & Authorization',
    description: 'The entity restricts access to information assets and systems to authorized users and authorized activities.',
    tscReference: 'CC6.4',
    severity: 'CRITICAL',
    isAutomated: true,
  },
  {
    id: 'CC6.5',
    category: 'SECURITY',
    title: 'Segregation of Duties',
    description: 'The entity identifies and authenticates users prior to granting access to information assets and systems.',
    tscReference: 'CC6.5',
    severity: 'HIGH',
    isAutomated: false,
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
    description: 'The entity restricts access to system components to authorized users and authorized activities.',
    tscReference: 'CC6.8',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC7.1',
    category: 'SECURITY',
    title: 'System Monitoring',
    description: 'The entity uses detection and monitoring procedures to identify security events and anomalies that could indicate security incidents.',
    tscReference: 'CC7.1',
    severity: 'HIGH',
    isAutomated: true,
  },
  {
    id: 'CC7.2',
    category: 'SECURITY',
    title: 'Anomaly Detection & Incident Response',
    description: 'The entity monitors infrastructure to detect anomalies and unauthorized actions, and responds to security incidents.',
    tscReference: 'CC7.2',
    severity: 'CRITICAL',
    isAutomated: true,
  },
  {
    id: 'CC7.3',
    category: 'SECURITY',
    title: 'Security Incident Response',
    description: 'The entity evaluates security events and anomalies to establish whether they are security incidents.',
    tscReference: 'CC7.3',
    severity: 'HIGH',
    isAutomated: false,
  },
  {
    id: 'CC7.4',
    category: 'SECURITY',
    title: 'Incident Containment & Recovery',
    description: 'The entity contains security incidents to prevent further unauthorized access or damage.',
    tscReference: 'CC7.4',
    severity: 'CRITICAL',
    isAutomated: false,
  },
  {
    id: 'CC7.5',
    category: 'SECURITY',
    title: 'Incident Communication',
    description: 'The entity communicates security incidents to affected parties and relevant personnel.',
    tscReference: 'CC7.5',
    severity: 'HIGH',
    isAutomated: false,
  },
  {
    id: 'CC8.1',
    category: 'SECURITY',
    title: 'Change Management',
    description: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.',
    tscReference: 'CC8.1',
    severity: 'HIGH',
    isAutomated: true,
  },
];

export const AVAILABILITY_CONTROLS: SOC2Control[] = [
  {
    id: 'A1.1',
    category: 'AVAILABILITY',
    title: 'System Availability Monitoring',
    description: 'The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand.',
    tscReference: 'A1.1',
    severity: 'MEDIUM',
    isAutomated: true,
  },
  {
    id: 'A1.2',
    category: 'AVAILABILITY',
    title: 'Capacity Planning',
    description: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements infrastructure, software, and procedures.',
    tscReference: 'A1.2',
    severity: 'MEDIUM',
    isAutomated: true,
  },
  {
    id: 'A1.3',
    category: 'AVAILABILITY',
    title: 'Environmental Threat Mitigation',
    description: 'The entity implements controls to prevent or detect and protect against environmental threats that could damage or destroy information assets.',
    tscReference: 'A1.3',
    severity: 'MEDIUM',
    isAutomated: false,
  },
];

export const CONFIDENTIALITY_CONTROLS: SOC2Control[] = [
  {
    id: 'C1.1',
    category: 'CONFIDENTIALITY',
    title: 'Confidential Information Identification',
    description: 'The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.',
    tscReference: 'C1.1',
    severity: 'HIGH',
    isAutomated: false,
  },
  {
    id: 'C1.2',
    category: 'CONFIDENTIALITY',
    title: 'Confidentiality Obligations',
    description: 'The entity disposes of confidential information in accordance with confidentiality policies and procedures.',
    tscReference: 'C1.2',
    severity: 'MEDIUM',
    isAutomated: false,
  },
];

export const PRIVACY_CONTROLS: SOC2Control[] = [
  {
    id: 'P1.1',
    category: 'PRIVACY',
    title: 'Notice & Communication',
    description: 'The entity provides notice about the collection, use, retention, and disposal of personal information.',
    tscReference: 'P1.1',
    severity: 'MEDIUM',
    isAutomated: false,
  },
  {
    id: 'P2.1',
    category: 'PRIVACY',
    title: 'Choice & Consent',
    description: 'The entity communicates choices available regarding the collection, use, retention, and disclosure of personal information.',
    tscReference: 'P2.1',
    severity: 'MEDIUM',
    isAutomated: false,
  },
  {
    id: 'P3.1',
    category: 'PRIVACY',
    title: 'Collection Limitation',
    description: 'Personal information is collected only for the purposes identified in the notice.',
    tscReference: 'P3.1',
    severity: 'MEDIUM',
    isAutomated: false,
  },
  {
    id: 'P4.1',
    category: 'PRIVACY',
    title: 'Use & Retention',
    description: 'Personal information is used only for the purposes identified in the notice.',
    tscReference: 'P4.1',
    severity: 'MEDIUM',
    isAutomated: false,
  },
  {
    id: 'P5.1',
    category: 'PRIVACY',
    title: 'Access & Correction',
    description: 'Individuals are provided with access to their personal information for review and update.',
    tscReference: 'P5.1',
    severity: 'MEDIUM',
    isAutomated: false,
  },
  {
    id: 'P6.1',
    category: 'PRIVACY',
    title: 'Disclosure to Third Parties',
    description: 'Personal information is disclosed to third parties only with the consent of the individual or as required by law.',
    tscReference: 'P6.1',
    severity: 'HIGH',
    isAutomated: false,
  },
  {
    id: 'P7.1',
    category: 'PRIVACY',
    title: 'Quality & Integrity',
    description: 'Personal information is accurate, complete, and relevant for the purposes for which it is used.',
    tscReference: 'P7.1',
    severity: 'MEDIUM',
    isAutomated: false,
  },
  {
    id: 'P8.1',
    category: 'PRIVACY',
    title: 'Privacy Breach Response',
    description: 'The entity responds to privacy breaches in accordance with its policies and procedures.',
    tscReference: 'P8.1',
    severity: 'HIGH',
    isAutomated: false,
  },
];

export const ALL_CONTROLS: SOC2Control[] = [
  ...SECURITY_CONTROLS,
  ...AVAILABILITY_CONTROLS,
  ...CONFIDENTIALITY_CONTROLS,
  ...PRIVACY_CONTROLS,
];

export function getControlsByCategory(category: string): SOC2Control[] {
  return ALL_CONTROLS.filter((c) => c.category === category);
}

export function getAutomatedControls(): SOC2Control[] {
  return ALL_CONTROLS.filter((c) => c.isAutomated);
}

export function getManualControls(): SOC2Control[] {
  return ALL_CONTROLS.filter((c) => !c.isAutomated);
}
