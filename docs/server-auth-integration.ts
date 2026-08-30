/**
 * Auth Integration for ACA Server
 * 
 * Add these lines to your existing src/api/server.ts
 */

import authRoutes from './routes/auth.routes';
import { authMiddleware, optionalAuthMiddleware } from './middleware/auth.middleware';

// ... existing imports ...

export function createServer() {
  const app = express();

  // ... existing middleware (cors, json, etc.) ...

  // Public routes (no auth required)
  app.use('/api/auth', authRoutes);
  app.get('/health', healthHandler);
  app.get('/health/ready', readinessHandler);

  // Protected routes — require valid JWT or API key
  app.use('/api/audit', authMiddleware, auditRoutes);
  app.use('/api/controls', authMiddleware, controlRoutes);
  app.use('/api/controls/custom', authMiddleware, customControlRoutes);
  app.use('/api/templates', authMiddleware, templateRoutes);
  app.use('/api/export', authMiddleware, exportRoutes);
  app.use('/api/adapters', authMiddleware, adapterRoutes);

  // Dashboard routes — optional auth (will redirect to login if not authenticated)
  app.use('/dashboard', optionalAuthMiddleware, dashboardRoutes);

  // ... rest of server setup ...
}
