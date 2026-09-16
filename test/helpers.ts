import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
} from 'jose';
import type { JWK, JWTPayload } from 'jose';

import { silentDpopLog } from '../src/dpop/logger';
import { accessTokenHash } from '../src/dpop/validate-ath';
import type { ReplayStore } from '../src/dpop/validate-jti';
import { verifyDpopRequest } from '../src/dpop/verify-dpop';

export const ISSUER = 'http://localhost:8080/realms/dpop-demo';
export const AUDIENCE = 'dpop-api';
export const RESOURCE_URI = 'http://localhost:3000/api/protected';
export const NOW = 1_700_000_000;

export class MemoryReplayStore implements ReplayStore {
  private readonly seen = new Set<string>();

  async consumeOnce(jkt: string, jti: string): Promise<boolean> {
    const key = `dpop:jti:${jkt}:${jti}`;
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    return true;
  }
}

export async function createAuthorizationServer() {
  const { publicKey, privateKey } = await generateKeyPair('RS256', {
    extractable: false,
  });
  const jwk = await exportJWK(publicKey);
  jwk.kid = 'test-as';
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  return {
    privateKey,
    jwks: createLocalJWKSet({ keys: [jwk] }),
  };
}

export async function createDpopKey() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', {
    extractable: false,
  });
  const exported = await exportJWK(publicKey);
  const publicJwk: JWK = {
    kty: 'EC',
    crv: exported.crv,
    x: exported.x,
    y: exported.y,
  };
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');
  return { publicKey, privateKey, publicJwk, jkt };
}

export async function signAccessToken(
  asPrivateKey: Parameters<SignJWT['sign']>[0],
  claims: JWTPayload
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: 'test-as', typ: 'at+jwt' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt(NOW)
    .setExpirationTime(NOW + 300)
    .sign(asPrivateKey);
}

export async function signDpopProof(options: {
  privateKey: Parameters<SignJWT['sign']>[0];
  publicJwk: JWK;
  payload: JWTPayload;
  typ?: string;
  alg?: string;
}): Promise<string> {
  return new SignJWT(options.payload)
    .setProtectedHeader({
      typ: options.typ ?? 'dpop+jwt',
      alg: options.alg ?? 'ES256',
      jwk: options.publicJwk,
    })
    .sign(options.privateKey);
}

export async function validPair() {
  const as = await createAuthorizationServer();
  const dpop = await createDpopKey();
  const accessToken = await signAccessToken(as.privateKey, {
    sub: 'alice',
    cnf: { jkt: dpop.jkt },
  });
  const proof = await signDpopProof({
    privateKey: dpop.privateKey,
    publicJwk: dpop.publicJwk,
    payload: {
      htm: 'GET',
      htu: RESOURCE_URI,
      iat: NOW,
      jti: 'jti-1',
      ath: accessTokenHash(accessToken),
    },
  });
  return { as, dpop, accessToken, proof };
}

export function verify(options: {
  as: Awaited<ReturnType<typeof createAuthorizationServer>>;
  accessToken: string;
  proof: string;
  replayStore?: ReplayStore;
  method?: string;
  httpUri?: string;
  nowSeconds?: number;
  authorizationHeader?: string;
}) {
  return verifyDpopRequest({
    method: options.method ?? 'GET',
    httpUri: options.httpUri ?? RESOURCE_URI,
    authorizationHeader: options.authorizationHeader ?? `DPoP ${options.accessToken}`,
    dpopHeader: options.proof,
    accessTokenJwks: options.as.jwks,
    issuer: ISSUER,
    audience: AUDIENCE,
    replayStore: options.replayStore ?? new MemoryReplayStore(),
    iatToleranceSeconds: 60,
    jtiTtlSeconds: 120,
    log: silentDpopLog,
    nowSeconds: options.nowSeconds ?? NOW,
  });
}
