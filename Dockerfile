# ============================================
# Autonomous Compliance Agent — Production Docker Image
# Multi-stage build for minimal attack surface
# ============================================

# --- Stage 1: Dependencies ---
FROM node:20-alpine AS deps
WORKDIR /app

# Install build dependencies for native modules
RUN apk add --no-cache libc6-compat python3 make g++

COPY package.json package-lock.json* ./
RUN npm ci --only=production && npm cache clean --force

# --- Stage 2: Builder ---
FROM node:20-alpine AS builder
WORKDIR /app

RUN apk add --no-cache libc6-compat python3 make g++

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npx prisma generate
RUN npm run build

# --- Stage 3: Production Runner ---
FROM node:20-alpine AS runner
WORKDIR /app

# Security: Run as non-root
RUN addgroup --system --gid 1001 compliance && \
    adduser --system --uid 1001 --ingroup compliance agent

# Install only runtime dependencies
RUN apk add --no-cache dumb-init curl

ENV NODE_ENV=production
ENV PORT=3000
ENV PRISMA_CLI_QUERY_ENGINE_TYPE=library

# Copy production dependencies
COPY --from=deps --chown=agent:compliance /app/node_modules ./node_modules
COPY --from=deps --chown=agent:compliance /app/package.json ./package.json

# Copy built application
COPY --from=builder --chown=agent:compliance /app/dist ./dist
COPY --from=builder --chown=agent:compliance /app/prisma ./prisma
COPY --from=builder --chown=agent:compliance /app/node_modules/.prisma ./node_modules/.prisma

# Create required directories
RUN mkdir -p /app/exports /app/logs && chown -R agent:compliance /app/exports /app/logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

USER agent

EXPOSE 3000

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
