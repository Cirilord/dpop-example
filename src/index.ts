import Redis from 'ioredis';

import { createApp } from './app';
import { config } from './config';

const redis = new Redis(config.redisUrl);
const app = createApp({
  redis,
  getPublicUrl: () => config.resourceServerPublicUrl,
  keycloakJwksUri: config.keycloakJwksUri,
  issuer: config.keycloakIssuer,
  audience: config.keycloakAudience,
  iatToleranceSeconds: config.dpopIatToleranceSeconds,
  jtiTtlSeconds: config.dpopJtiTtlSeconds,
  verboseDpopLogs: config.verboseDpopLogs,
});

try {
  await app.listen({ port: config.port, host: '0.0.0.0' });
  console.log(`Resource server listening on ${config.resourceServerPublicUrl}`);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}

const shutdown = async () => {
  await app.close();
  await redis.quit();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
