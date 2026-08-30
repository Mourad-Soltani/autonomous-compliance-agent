import { z } from 'zod';

export const UserRoleSchema = z.enum(['ADMIN', 'OWNER', 'AUDITOR', 'USER']);
export type UserRole = z.infer<typeof UserRoleSchema>;

export const UserStatusSchema = z.enum(['ACTIVE', 'SUSPENDED', 'PENDING']);
export type UserStatus = z.infer<typeof UserStatusSchema>;

export const UserSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string().nullable(),
  avatar: z.string().nullable(),
  role: UserRoleSchema,
  status: UserStatusSchema,
  organizationId: z.string().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
  organization: z.unknown().nullable(),
});
export type User = z.infer<typeof UserSchema>;

export const AuthContextSchema = z.object({
  user: UserSchema,
  scopes: z.array(z.string()),
});
export type AuthContext = z.infer<typeof AuthContextSchema>;

export const JWTPayloadSchema = z.object({
  userId: z.string(),
  email: z.string().email(),
  role: UserRoleSchema,
  orgId: z.string().nullable(),
  scopes: z.array(z.string()),
  iat: z.number().optional(),
  exp: z.number().optional(),
});
export type JWTPayload = z.infer<typeof JWTPayloadSchema>;
