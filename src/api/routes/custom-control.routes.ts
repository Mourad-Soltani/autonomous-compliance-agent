import { Router, Request, Response } from 'express';
import { z } from 'zod';

const CustomControlSchema = z.object({
  id: z.string().min(1).regex(/^[A-Z0-9-]+$/),
  title: z.string().min(1).max(200),
  description: z.string().min(1).max(2000),
  category: z.enum(['SECURITY', 'AVAILABILITY', 'CONFIDENTIALITY', 'PROCESSING_INTEGRITY', 'PRIVACY']),
  soc2Mapping: z.string().regex(/^[A-Z0-9]+\.\d+$/),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  adapter: z.enum(['aws', 'azure', 'gcp', 'github', 'custom']),
  checkType: z.enum(['api', 'cli', 'config', 'custom']),
  checkConfig: z.string().min(1),
  remediationEnabled: z.boolean(),
  remediationConfig: z.string().optional(),
  automated: z.boolean(),
});

type CustomControl = z.infer<typeof CustomControlSchema> & {
  createdAt: string;
  updatedAt: string;
  active: boolean;
};

interface CheckResult {
  compliant: boolean;
  [key: string]: unknown;
}

const customControls: Map<string, CustomControl> = new Map();

const router = Router();

router.get('/', (_req: Request, res: Response) => {
  const controls = Array.from(customControls.values());
  res.json({
    controls,
    count: controls.length,
    automated: controls.filter(c => c.automated).length,
    manual: controls.filter(c => !c.automated).length,
  });
});

router.get('/:id', (req: Request, res: Response) => {
  const control = customControls.get(req.params.id);
  if (!control) {
    return res.status(404).json({ error: 'Custom control not found' });
  }
  res.json(control);
});

router.post('/', (req: Request, res: Response) => {
  try {
    const parsed = CustomControlSchema.parse(req.body);

    if (customControls.has(parsed.id)) {
      return res.status(409).json({ error: `Control with ID '${parsed.id}' already exists` });
    }

    const control: CustomControl = {
      ...parsed,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      active: true,
    };

    customControls.set(parsed.id, control);

    res.status(201).json({
      message: 'Custom control created successfully',
      control,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors.map(e => ({ field: e.path.join('.'), message: e.message })),
      });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/:id', (req: Request, res: Response) => {
  const existing = customControls.get(req.params.id);
  if (!existing) {
    return res.status(404).json({ error: 'Custom control not found' });
  }

  try {
    const parsed = CustomControlSchema.partial().parse(req.body);

    const updated: CustomControl = {
      ...existing,
      ...parsed,
      updatedAt: new Date().toISOString(),
    };

    customControls.set(req.params.id, updated);

    res.json({
      message: 'Custom control updated successfully',
      control: updated,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors.map(e => ({ field: e.path.join('.'), message: e.message })),
      });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/:id', (req: Request, res: Response) => {
  if (!customControls.has(req.params.id)) {
    return res.status(404).json({ error: 'Custom control not found' });
  }

  customControls.delete(req.params.id);
  res.json({ message: 'Custom control deleted successfully' });
});

router.post('/:id/activate', (req: Request, res: Response) => {
  const control = customControls.get(req.params.id);
  if (!control) {
    return res.status(404).json({ error: 'Custom control not found' });
  }

  control.active = true;
  control.updatedAt = new Date().toISOString();
  res.json({ message: 'Control activated', control });
});

router.post('/:id/deactivate', (req: Request, res: Response) => {
  const control = customControls.get(req.params.id);
  if (!control) {
    return res.status(404).json({ error: 'Custom control not found' });
  }

  control.active = false;
  control.updatedAt = new Date().toISOString();
  res.json({ message: 'Control deactivated', control });
});

router.post('/:id/test', async (req: Request, res: Response) => {
  const control = customControls.get(req.params.id);
  if (!control) {
    return res.status(404).json({ error: 'Custom control not found' });
  }

  try {
    const checkFn = new Function('return ' + control.checkConfig)();
    const results: CheckResult[] = await checkFn();

    res.json({
      controlId: control.id,
      testedAt: new Date().toISOString(),
      results,
      passed: results.every((r) => r.compliant),
    });
  } catch (error) {
    res.status(500).json({
      error: 'Check execution failed',
      message: error instanceof Error ? error.message : String(error),
    });
  }
});

export default router;
