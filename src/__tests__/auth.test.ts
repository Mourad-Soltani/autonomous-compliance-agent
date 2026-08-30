import { describe, it, expect } from 'vitest';
import { JWTPayloadSchema, UserRoleSchema } from '../types/auth.js';

describe('auth types', () => {
  it('validates a correct JWT payload', () => {
    const payload = {
      userId: 'user-1',
      email: 'test@example.com',
      role: 'ADMIN',
      orgId: 'org-1',
      scopes: ['read:audit'],
    };

    const result = JWTPayloadSchema.parse(payload);
    expect(result.userId).toBe('user-1');
    expect(result.role).toBe('ADMIN');
  });

  it('rejects invalid email', () => {
    expect(() =>
      JWTPayloadSchema.parse({
        userId: 'user-1',
        email: 'not-an-email',
        role: 'ADMIN',
        scopes: [],
      })
    ).toThrow();
  });

  it('rejects invalid role', () => {
    expect(() =>
      JWTPayloadSchema.parse({
        userId: 'user-1',
        email: 'test@example.com',
        role: 'SUPERADMIN',
        scopes: [],
      })
    ).toThrow();
  });
});
