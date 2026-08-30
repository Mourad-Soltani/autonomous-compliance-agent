import { Request, Response, NextFunction } from 'express';
import { z, ZodSchema } from 'zod';

export const PaginationQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(10),
  offset: z.coerce.number().int().min(0).default(0),
});

export const SeedTemplatesQuerySchema = z.object({
  category: z.string().optional(),
  automatedOnly: z.coerce.boolean().default(false),
  manualOnly: z.coerce.boolean().default(false),
});

export const ExportFormatQuerySchema = z.object({
  format: z.enum(['csv', 'json', 'markdown', 'html']).default('json'),
});

export function validateQuery(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.query);
    if (!result.success) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Invalid query parameters',
        details: result.error.flatten().fieldErrors,
      });
    }
    // Attach validated data to request for downstream use
    (req as any).validatedQuery = result.data;
    next();
  };
}

export function validateBody(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Invalid request body',
        details: result.error.flatten().fieldErrors,
      });
    }
    (req as any).validatedBody = result.data;
    next();
  };
}
