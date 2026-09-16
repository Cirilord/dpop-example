import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import type Redis from 'ioredis';
import { createRemoteJWKSet } from 'jose';

import { DpopError } from './dpop/errors';
import { createDpopLog } from './dpop/logger';
import { buildResourceUri } from './dpop/validate-htu';
import { verifyDpopRequest } from './dpop/verify-dpop';
import { RedisReplayStore } from './redis-replay-store';

export type CreateAppOptions = {
  redis: Redis;
  getPublicUrl: () => string;
  keycloakJwksUri: string;
  issuer: string;
  audience: string;
  iatToleranceSeconds: number;
  jtiTtlSeconds: number;
  verboseDpopLogs: boolean;
  logger?: boolean;
};

export function createApp(options: CreateAppOptions): FastifyInstance {
  const app = Fastify({ logger: options.logger ?? true });
  const replayStore = new RedisReplayStore(options.redis);
  const accessTokenJwks = createRemoteJWKSet(new URL(options.keycloakJwksUri));

  app.get('/health', async () => ({ ok: true }));

  app.get('/api/protected', async (request, reply) => {
    const httpUri = buildResourceUri(options.getPublicUrl(), request.url);

    try {
      await verifyDpopRequest({
        method: request.method,
        httpUri,
        authorizationHeader: request.headers.authorization,
        dpopHeader: request.headers.dpop as string | string[] | undefined,
        accessTokenJwks,
        issuer: options.issuer,
        audience: options.audience,
        replayStore,
        iatToleranceSeconds: options.iatToleranceSeconds,
        jtiTtlSeconds: options.jtiTtlSeconds,
        log: createDpopLog(options.verboseDpopLogs),
      });
    } catch (error) {
      if (error instanceof DpopError) {
        const escaped = error.message.replace(/"/g, "'");
        return reply
          .status(401)
          .header('WWW-Authenticate', `DPoP error="${error.error}", error_description="${escaped}"`)
          .send({
            error: error.error,
            error_description: error.message,
          });
      }
      throw error;
    }

    return { message: 'Hello from a DPoP protected API' };
  });

  app.setErrorHandler((error, _request, reply) => {
    app.log.error(error);
    reply.status(500).send({
      error: 'server_error',
      error_description: 'Unexpected server error',
    });
  });

  return app;
}

export function listenOrigin(app: FastifyInstance): string {
  const address = app.server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Unexpected server address');
  }
  return `http://127.0.0.1:${address.port}`;
}
