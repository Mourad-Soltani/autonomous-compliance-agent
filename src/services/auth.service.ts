import { PrismaClient, User, ApiKey, Organization } from '@prisma/client';
import { hash, compare } from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';
import { randomBytes, createHash } from 'crypto';
import { z } from 'zod';

const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || 'aca-dev-secret-change-in-production';
const JWT_EXPIRES_IN = '7d';
const REFRESH_EXPIRES_IN = '30d';

// ============================================
// Schemas
// ============================================

export const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(100),
  name: z.string().min(1).max(100),
  organizationName: z.string().min(1).max(100).optional(),
});

export const CreateApiKeySchema = z.object({
  name: z.string().min(1).max(100),
  scopes: z.array(z.enum(['read:audit', 'write:controls', 'write:remediate', 'admin'])),
  expiresInDays: z.number().int().min(1).max(365).optional(),
});

// ============================================
// Types
// ============================================

export interface AuthContext {
  user: User & { organization: Organization | null };
  apiKey?: ApiKey;
  scopes: string[];
}

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
  orgId?: string;
  scopes: string[];
  iat: number;
  exp: number;
}

// ============================================
// Password Auth
// ============================================

export async function registerUser(data: z.infer<typeof RegisterSchema>) {
  const existing = await prisma.user.findUnique({ where: { email: data.email } });
  if (existing) {
    throw new Error('User already exists');
  }

  const passwordHash = await hash(data.password, 12);

  let organizationId: string | undefined;
  if (data.organizationName) {
    const org = await prisma.organization.create({
      data: {
        name: data.organizationName,
        slug: data.organizationName.toLowerCase().replace(/\s+/g, '-'),
        plan: 'FREE',
      },
    });
    organizationId = org.id;
  }

  const user = await prisma.user.create({
    data: {
      email: data.email,
      name: data.name,
      role: organizationId ? 'OWNER' : 'MEMBER',
      organizationId,
    },
    include: { organization: true },
  });

  // Create audit log
  await prisma.auditLog.create({
    data: {
      userId: user.id,
      action: 'user.register',
      resource: `user:${user.id}`,
      metadata: { email: user.email },
    },
  });

  return { user, token: generateToken(user) };
}

export async function loginUser(data: z.infer<typeof LoginSchema>) {
  const user = await prisma.user.findUnique({
    where: { email: data.email },
    include: { organization: true },
  });

  if (!user) {
    throw new Error('Invalid credentials');
  }

  // In production, compare against password hash stored in DB
  // For demo: simple check (replace with bcrypt compare)
  const valid = await compare(data.password, user.passwordHash || '');
  if (!valid) {
    throw new Error('Invalid credentials');
  }

  await prisma.auditLog.create({
    data: {
      userId: user.id,
      action: 'user.login',
      resource: `user:${user.id}`,
    },
  });

  return { user, token: generateToken(user) };
}

// ============================================
// JWT
// ============================================

export function generateToken(user: User & { organization: Organization | null }): string {
  const scopes = getScopesForRole(user.role);
  return sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
      orgId: user.organizationId,
      scopes,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

export function verifyToken(token: string): TokenPayload {
  return verify(token, JWT_SECRET) as TokenPayload;
}

export async function createSession(userId: string): Promise<string> {
  const token = randomBytes(32).toString('hex');
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30);

  await prisma.session.create({
    data: {
      token,
      userId,
      expiresAt,
    },
  });

  return token;
}

// ============================================
// API Keys
// ============================================

export async function createApiKey(
  userId: string,
  data: z.infer<typeof CreateApiKeySchema>
): Promise<{ key: string; apiKey: ApiKey }> {
  const rawKey = `aca_${randomBytes(32).toString('hex')}`;
  const keyHash = createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKey.slice(0, 8);

  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { organization: true },
  });

  if (!user) throw new Error('User not found');

  const expiresAt = data.expiresInDays
    ? new Date(Date.now() + data.expiresInDays * 24 * 60 * 60 * 1000)
    : null;

  const apiKey = await prisma.apiKey.create({
    data: {
      name: data.name,
      keyHash,
      keyPrefix,
      scopes: data.scopes,
      userId,
      organizationId: user.organizationId,
      expiresAt,
    },
  });

  await prisma.auditLog.create({
    data: {
      userId,
      action: 'apikey.create',
      resource: `apikey:${apiKey.id}`,
      metadata: { name: data.name, scopes: data.scopes },
    },
  });

  return { key: rawKey, apiKey };
}

export async function validateApiKey(key: string): Promise<AuthContext | null> {
  const keyHash = createHash('sha256').update(key).digest('hex');

  const apiKey = await prisma.apiKey.findUnique({
    where: { keyHash },
    include: {
      user: { include: { organization: true } },
      organization: true,
    },
  });

  if (!apiKey || apiKey.revokedAt) return null;
  if (apiKey.expiresAt && apiKey.expiresAt < new Date()) return null;

  // Update last used
  await prisma.apiKey.update({
    where: { id: apiKey.id },
    data: { lastUsedAt: new Date() },
  });

  const user = apiKey.user;
  if (!user) return null;

  return {
    user: user as User & { organization: Organization | null },
    apiKey,
    scopes: apiKey.scopes,
  };
}

export async function revokeApiKey(userId: string, keyId: string) {
  const apiKey = await prisma.apiKey.findFirst({
    where: { id: keyId, userId },
  });

  if (!apiKey) throw new Error('API key not found');

  await prisma.apiKey.update({
    where: { id: keyId },
    data: { revokedAt: new Date() },
  });

  await prisma.auditLog.create({
    data: {
      userId,
      action: 'apikey.revoke',
      resource: `apikey:${keyId}`,
    },
  });
}

export async function listApiKeys(userId: string) {
  return prisma.apiKey.findMany({
    where: { userId, revokedAt: null },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      scopes: true,
      lastUsedAt: true,
      expiresAt: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });
}

// ============================================
// SSO / OIDC
// ============================================

export async function getSSOConfig(organizationSlug: string) {
  const org = await prisma.organization.findUnique({
    where: { slug: organizationSlug },
    include: { ssoConfig: true },
  });

  if (!org?.ssoConfig?.enabled) return null;
  return org.ssoConfig;
}

export async function createOrUpdateSSOConfig(
  orgId: string,
  data: {
    provider: string;
    clientId: string;
    clientSecret: string;
    issuerUrl: string;
    enabled: boolean;
  }
) {
  return prisma.sSOConfig.upsert({
    where: { organizationId: orgId },
    update: {
      provider: data.provider as any,
      clientId: data.clientId,
      clientSecret: data.clientSecret,
      issuerUrl: data.issuerUrl,
      enabled: data.enabled,
    },
    create: {
      organizationId: orgId,
      provider: data.provider as any,
      clientId: data.clientId,
      clientSecret: data.clientSecret,
      issuerUrl: data.issuerUrl,
      enabled: data.enabled,
    },
  });
}

// ============================================
// Helpers
// ============================================

function getScopesForRole(role: string): string[] {
  switch (role) {
    case 'OWNER':
      return ['read:audit', 'write:controls', 'write:remediate', 'admin', 'write:org'];
    case 'ADMIN':
      return ['read:audit', 'write:controls', 'write:remediate', 'admin'];
    case 'MEMBER':
      return ['read:audit', 'write:controls'];
    case 'VIEWER':
      return ['read:audit'];
    default:
      return ['read:audit'];
  }
}

export function requireScope(scopes: string[], required: string): boolean {
  return scopes.includes('admin') || scopes.includes(required);
}
