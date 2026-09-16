import Redis from 'ioredis';
import { decodeJwt } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  callProtectedApi,
  createDpopProof,
  generateDpopKeys,
  requestAccessToken,
} from '../../demo/dpop-client';
import { createApp, listenOrigin } from '../../src/app';
import { config } from '../../src/config';

const KEYCLOAK_URL = process.env.KEYCLOAK_URL ?? 'http://localhost:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM ?? 'dpop-demo';
const TOKEN_ENDPOINT = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;

async function waitForKeycloak(timeoutMs = 90_000): Promise<void> {
  const wellKnown = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration`;
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(wellKnown);
      if (response.ok) return;
    } catch {
      // Keycloak is still booting.
    }
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
  throw new Error(
    `Keycloak did not become ready at ${wellKnown}. Start it with: docker compose up -d`
  );
}

describe('DPoP e2e against Keycloak + Redis', () => {
  const redis = new Redis(config.redisUrl);
  let publicUrl = 'http://127.0.0.1';
  const app = createApp({
    redis,
    getPublicUrl: () => publicUrl,
    keycloakJwksUri: config.keycloakJwksUri,
    issuer: config.keycloakIssuer,
    audience: config.keycloakAudience,
    iatToleranceSeconds: config.dpopIatToleranceSeconds,
    jtiTtlSeconds: config.dpopJtiTtlSeconds,
    verboseDpopLogs: false,
    logger: false,
  });

  let protectedUrl = '';

  const client = {
    tokenEndpoint: TOKEN_ENDPOINT,
    clientId: process.env.KEYCLOAK_CLIENT_ID ?? 'dpop-client',
    username: process.env.KEYCLOAK_USERNAME ?? 'alice',
    password: process.env.KEYCLOAK_PASSWORD ?? 'alice',
  };

  beforeAll(async () => {
    await waitForKeycloak();
    await app.listen({ port: 0, host: '127.0.0.1' });
    publicUrl = listenOrigin(app);
    protectedUrl = `${publicUrl}/api/protected`;
  }, 120_000);

  afterAll(async () => {
    await app.close();
    await redis.quit();
  });

  it('issues a DPoP-bound token and accepts a matching proof', async () => {
    const keys = await generateDpopKeys();
    const { token, dpopProof: loginProof } = await requestAccessToken(client, keys);
    const payload = decodeJwt(token.access_token) as { cnf?: { jkt?: string } };

    expect(token.token_type.toLowerCase()).toBe('dpop');
    expect(payload.cnf?.jkt).toBe(keys.jkt);
    expect(decodeJwt(loginProof).ath).toBeUndefined();

    const apiProof = await createDpopProof({
      url: protectedUrl,
      method: 'GET',
      accessToken: token.access_token,
      keypair: keys,
    });
    expect(decodeJwt(apiProof).ath).toBeTypeOf('string');

    const first = await callProtectedApi(protectedUrl, token.access_token, apiProof);
    expect(first.status).toBe(200);
    expect(first.body).toEqual({ message: 'Hello from a DPoP protected API' });
  });

  it('rejects a replayed DPoP proof', async () => {
    const keys = await generateDpopKeys();
    const { token } = await requestAccessToken(client, keys);
    const apiProof = await createDpopProof({
      url: protectedUrl,
      method: 'GET',
      accessToken: token.access_token,
      keypair: keys,
    });

    const first = await callProtectedApi(protectedUrl, token.access_token, apiProof);
    const replay = await callProtectedApi(protectedUrl, token.access_token, apiProof);

    expect(first.status).toBe(200);
    expect(replay.status).toBe(401);
    expect(replay.body).toMatchObject({ error: 'dpop_replay_detected' });
  });

  it('rejects an Access Token used with a different DPoP key', async () => {
    const keys = await generateDpopKeys();
    const attacker = await generateDpopKeys();
    const { token } = await requestAccessToken(client, keys);
    const stolenProof = await createDpopProof({
      url: protectedUrl,
      method: 'GET',
      accessToken: token.access_token,
      keypair: attacker,
    });

    const stolen = await callProtectedApi(protectedUrl, token.access_token, stolenProof);
    expect(stolen.status).toBe(401);
    expect(stolen.body).toMatchObject({ error: 'dpop_key_mismatch' });
  });
});
