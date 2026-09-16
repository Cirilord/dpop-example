import type { JWK } from 'jose';

import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

const PRIVATE_JWK_PARAMS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'] as const;

/**
 * The DPoP header carries the public key that signed the proof.
 * That key is untrusted until the signature check succeeds, but we
 * still refuse anything that is not an ES256 public JWK up front.
 */
export function validateJwk(jwk: unknown, log: DpopLog): JWK {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) {
    log.fail('jwk', 'header.jwk is missing or not an object');
    throw DpopErrors.invalidJwk('DPoP header.jwk must be a public JWK');
  }

  const key = jwk as Record<string, unknown>;

  for (const param of PRIVATE_JWK_PARAMS) {
    if (param in key) {
      log.fail('jwk', `JWK contains private parameter "${param}"`);
      throw DpopErrors.invalidJwk('DPoP JWK must not contain private parameters');
    }
  }

  if (key.kty !== 'EC') {
    log.fail('jwk', `expected kty=EC, received ${String(key.kty)}`);
    throw DpopErrors.invalidJwk('DPoP JWK must be an EC public key');
  }

  if (key.crv !== 'P-256') {
    log.fail('jwk', `expected crv=P-256, received ${String(key.crv)}`);
    throw DpopErrors.invalidJwk('DPoP JWK must use curve P-256');
  }

  if (typeof key.x !== 'string' || typeof key.y !== 'string') {
    log.fail('jwk', 'EC JWK is missing public coordinates x/y');
    throw DpopErrors.invalidJwk('DPoP JWK must include public coordinates x and y');
  }

  if (key.alg !== undefined && key.alg !== 'ES256') {
    log.fail('jwk', `JWK alg must be ES256 when present, received ${String(key.alg)}`);
    throw DpopErrors.invalidJwk('DPoP JWK alg must be ES256');
  }

  if (key.use !== undefined && key.use !== 'sig') {
    log.fail('jwk', `JWK use must be sig when present, received ${String(key.use)}`);
    throw DpopErrors.invalidJwk('DPoP JWK use must be sig');
  }

  log.ok('jwk', 'EC P-256 public key (no private parameters)');
  return {
    kty: 'EC',
    crv: 'P-256',
    x: key.x,
    y: key.y,
  };
}
