import { config as loadEnv } from 'dotenv';

loadEnv({ quiet: true });

function required(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function integer(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

export const config = {
  port: integer('SERVER_PORT', 3000),
  resourceServerPublicUrl: required('RESOURCE_SERVER_PUBLIC_URL', 'http://localhost:3000').replace(
    /\/$/,
    ''
  ),
  keycloakIssuer: required('KEYCLOAK_ISSUER', 'http://localhost:8080/realms/dpop-demo'),
  keycloakAudience: required('KEYCLOAK_AUDIENCE', 'dpop-api'),
  keycloakJwksUri: required(
    'KEYCLOAK_JWKS_URI',
    'http://localhost:8080/realms/dpop-demo/protocol/openid-connect/certs'
  ),
  dpopIatToleranceSeconds: integer('DPOP_IAT_TOLERANCE_SECONDS', 60),
  dpopJtiTtlSeconds: integer('DPOP_JTI_TTL_SECONDS', 120),
  redisUrl: required('REDIS_URL', 'redis://127.0.0.1:6379'),
  verboseDpopLogs: (process.env.DPOP_VERBOSE ?? 'true') !== 'false',
};
