import { Request, Response, NextFunction } from 'express';
import { verifyToken, validateApiKey, requireScope, AuthContext } from '../services/auth.service.js';
import { JWTPayloadSchema } from '../../types/auth.js';

// Extend Express Request
declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

/**
 * JWT Bearer Token Authentication
 * Header: Authorization: Bearer <jwt-token>
 */
export async function authMiddleware(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Missing authorization header' });
    }

    // Try API Key first (aca_ prefix)
    if (authHeader.startsWith('Bearer aca_')) {
      const apiKey = authHeader.slice(7); // Remove "Bearer "
      const context = await validateApiKey(apiKey);

      if (!context) {
        return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or revoked API key' });
      }

      req.auth = context;
      return next();
    }

    // Try JWT
    if (authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      const payloadRaw = verifyToken(token);
      const payload = JWTPayloadSchema.parse(payloadRaw);

      req.auth = {
        user: {
          id: payload.userId,
          email: payload.email,
          name: null,
          avatar: null,
          role: payload.role,
          status: 'ACTIVE',
          organizationId: payload.orgId,
          createdAt: new Date(),
          updatedAt: new Date(),
          organization: null,
        } as any,  // Cast needed until Prisma User type is fully aligned
        scopes: payload.scopes,
      };

      return next();
    }

    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid authorization format' });
  } catch (error) {
    if (error instanceof Error && error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid token' });
    }
    if (error instanceof Error && error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Unauthorized', message: 'Token expired' });
    }
    return res.status(500).json({ error: 'Internal Server Error', message: 'Authentication failed' });
  }
}

/**
 * Optional Authentication — attaches auth if present, doesn't reject
 */
export async function optionalAuthMiddleware(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return next();

    if (authHeader.startsWith('Bearer aca_')) {
      const apiKey = authHeader.slice(7);
      const context = await validateApiKey(apiKey);
      if (context) req.auth = context;
      return next();
    }

    if (authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      const payloadRaw = verifyToken(token);
      const payload = JWTPayloadSchema.parse(payloadRaw);

      req.auth = {
        user: {
          id: payload.userId,
          email: payload.email,
          name: null,
          avatar: null,
          role: payload.role,
          status: 'ACTIVE',
          organizationId: payload.orgId,
          createdAt: new Date(),
          updatedAt: new Date(),
          organization: null,
        } as any,
        scopes: payload.scopes,
      };
    }

    next();
  } catch {
    next();
  }
}

/**
 * Scope-based Authorization
 * Usage: requireAuth('read:audit')
 */
export function requireAuth(...requiredScopes: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
    }

    const hasScope = requiredScopes.some(scope => requireScope(req.auth!.scopes, scope));

    if (!hasScope) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Insufficient permissions. Required: ${requiredScopes.join(' or ')}`,
      });
    }

    next();
  };
}

/**
 * Role-based Authorization
 * Usage: requireRole('ADMIN', 'OWNER')
 */
export function requireRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.auth.user.role)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Required role: ${allowedRoles.join(' or ')}`,
      });
    }

    next();
  };
}
