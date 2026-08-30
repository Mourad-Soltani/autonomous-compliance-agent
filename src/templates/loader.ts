import { ALL_CONTROLS, getControlsByCategory, getAutomatedControls, getManualControls } from './controls.js';
import { SOC2Control } from '../types/policy.js';
import { syncControls } from '../core/db.js';

export interface TemplateSeedOptions {
  category?: 'SECURITY' | 'AVAILABILITY' | 'CONFIDENTIALITY' | 'PRIVACY' | 'PROCESSING_INTEGRITY' | 'ALL';
  automatedOnly?: boolean;
  manualOnly?: boolean;
  controlIds?: string[];
}

/**
 * Seed the database with pre-built SOC 2 control templates.
 */
export async function seedTemplates(options: TemplateSeedOptions = {}): Promise<{
  seeded: number;
  controls: SOC2Control[];
}> {
  let controlsToSeed: SOC2Control[] = [];

  if (options.controlIds && options.controlIds.length > 0) {
    // Seed specific controls by ID
    controlsToSeed = ALL_CONTROLS.filter((c) => options.controlIds!.includes(c.id));
  } else if (options.automatedOnly) {
    controlsToSeed = getAutomatedControls();
  } else if (options.manualOnly) {
    controlsToSeed = getManualControls();
  } else if (options.category && options.category !== 'ALL') {
    controlsToSeed = getControlsByCategory(options.category);
  } else {
    controlsToSeed = ALL_CONTROLS;
  }

  if (controlsToSeed.length === 0) {
    return { seeded: 0, controls: [] };
  }

  await syncControls(controlsToSeed);

  return {
    seeded: controlsToSeed.length,
    controls: controlsToSeed,
  };
}

/**
 * Get template statistics.
 */
export function getTemplateStats(): {
  total: number;
  byCategory: Record<string, number>;
  automated: number;
  manual: number;
} {
  const byCategory: Record<string, number> = {};
  for (const control of ALL_CONTROLS) {
    byCategory[control.category] = (byCategory[control.category] || 0) + 1;
  }

  return {
    total: ALL_CONTROLS.length,
    byCategory,
    automated: getAutomatedControls().length,
    manual: getManualControls().length,
  };
}

/**
 * List all available templates.
 */
export function listTemplates(): SOC2Control[] {
  return ALL_CONTROLS;
}
