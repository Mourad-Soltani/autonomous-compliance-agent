import { Router, Request, Response } from 'express';
import { z } from 'zod';
import {
  registerUser,
  loginUser,
  createApiKey,
  revokeApiKey,
  listApiKeys,
  getSSOConfig,
  createOrUpdateSSOConfig,
  LoginSchema,
  RegisterSchema,
  CreateApiKeySchema,
} from '../../services/auth.service.js';
import { authMiddleware, requireAuth, requireRole } from '../middleware/auth.middleware.js';

const router = Router();

// ============================================
// Public Routes
// ============================================

router.post('/register', async (req: Request, res: Response) => {
  try {
    const data = RegisterSchema.parse(req.body);
    const result = await registerUser(data);
    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: result.user.id,
        email: result.user.email,
        name: result.user.name,
        role: result.user.role,
      },
      token: result.token,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation failed', details: error.errors });
    }
    if (error instanceof Error) {
      return res.status(409).json({ error: error.message });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', async (req: Request, res: Response) => {
  try {
    const data = LoginSchema.parse(req.body);
    const result = await loginUser(data);
    res.json({
      message: 'Login successful',
      user: {
        id: result.user.id,
        email: result.user.email,
        name: result.user.name,
        role: result.user.role,
        organization: result.user.organization,
      },
      token: result.token,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation failed', details: error.errors });
    }
    if (error instanceof Error) {
      return res.status(401).json({ error: error.message });
    }
    res.status(500).json({ error: 'Login failed' });
  }
});

router.get('/sso/:slug', async (req: Request, res: Response) => {
  try {
    const config = await getSSOConfig(req.params.slug);
    if (!config) {
      return res.status(404).json({ error: 'SSO not configured for this organization' });
    }
    res.json({
      provider: config.provider,
      issuerUrl: config.issuerUrl,
      authorizationUrl: config.authorizationUrl,
      scopes: config.scopes,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch SSO config' });
  }
});

// ============================================
// Protected Routes
// ============================================

router.use(authMiddleware);

router.get('/me', (req: Request, res: Response) => {
  if (!req.auth) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({
    user: {
      id: req.auth.user.id,
      email: req.auth.user.email,
      name: req.auth.user.name,
      role: req.auth.user.role,
      organization: req.auth.user.organization,
    },
    scopes: req.auth.scopes,
  });
});

router.get('/api-keys', async (req: Request, res: Response) => {
  try {
    const keys = await listApiKeys(req.auth!.user.id);
    res.json({ keys });
  } catch (error) {
    res.status(500).json({ error: 'Failed to list API keys' });
  }
});

router.post('/api-keys', requireAuth('admin'), async (req: Request, res: Response) => {
  try {
    const data = CreateApiKeySchema.parse(req.body);
    const result = await createApiKey(req.auth!.user.id, data);
    res.status(201).json({
      message: 'API key created',
      key: result.key,
      apiKey: {
        id: result.apiKey.id,
        name: result.apiKey.name,
        prefix: result.apiKey.keyPrefix,
        scopes: result.apiKey.scopes,
        expiresAt: result.apiKey.expiresAt,
      },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation failed', details: error.errors });
    }
    res.status(500).json({ error: 'Failed to create API key' });
  }
});

router.delete('/api-keys/:id', requireAuth('admin'), async (req: Request, res: Response) => {
  try {
    await revokeApiKey(req.auth!.user.id, req.params.id);
    res.json({ message: 'API key revoked' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to revoke API key' });
  }
});

router.post('/sso-config', requireRole('OWNER', 'ADMIN'), async (req: Request, res: Response) => {
  try {
    const orgId = req.auth!.user.organizationId;
    if (!orgId) {
      return res.status(400).json({ error: 'User not associated with an organization' });
    }

    const config = await createOrUpdateSSOConfig(orgId, req.body);
    res.json({
      message: 'SSO configuration updated',
      config: {
        provider: config.provider,
        issuerUrl: config.issuerUrl,
        enabled: config.enabled,
      },
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update SSO config' });
  }
});

export default router;
