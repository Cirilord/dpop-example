import { compactVerify, decodeJwt } from 'jose';
import type { JWTVerifyGetKey } from 'jose';

import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

const ACCESS_TOKEN_ALGS = ['RS256', 'PS256', 'ES256'] as const;

function audienceIncludes(aud: unknown, expected: string): boolean {
  if (typeof aud === 'string') return aud === expected;
  if (Array.isArray(aud)) return aud.includes(expected);
  return false;
}

/**
 * Standard Access Token checks, independent of DPoP:
 * signature via Keycloak JWKS, then iss / aud / exp / nbf.
 *
 * DPoP-bound tokens must still be valid JWTs. CNF is checked later.
 */
export async function validateAccessToken(
  accessToken: string,
  jwks: JWTVerifyGetKey,
  issuer: string,
  audience: string,
  log: DpopLog,
  nowSeconds = Math.floor(Date.now() / 1000)
): Promise<Record<string, unknown>> {
  try {
    await compactVerify(accessToken, jwks, {
      algorithms: [...ACCESS_TOKEN_ALGS],
    });
    log.ok('Access Token signature');
  } catch {
    log.fail('Access Token signature');
    throw DpopErrors.invalidAccessToken('Access Token signature is invalid');
  }

  const payload = decodeJwt(accessToken) as Record<string, unknown>;

  if (payload.iss !== issuer) {
    log.fail('issuer', `expected: ${issuer}\nreceived: ${String(payload.iss)}`);
    throw DpopErrors.invalidAccessToken('Invalid issuer');
  }
  log.ok('issuer', issuer);

  if (!audienceIncludes(payload.aud, audience)) {
    log.fail('audience', `expected: ${audience}\nreceived: ${JSON.stringify(payload.aud)}`);
    throw DpopErrors.invalidAccessToken('Invalid audience');
  }
  log.ok('audience', audience);

  if (typeof payload.exp !== 'number' || payload.exp <= nowSeconds) {
    log.fail('expiration', `exp: ${String(payload.exp)}`);
    throw DpopErrors.invalidAccessToken('Access Token expired');
  }
  log.ok('expiration');

  if (typeof payload.nbf === 'number' && payload.nbf > nowSeconds) {
    log.fail('nbf', `nbf: ${payload.nbf}`);
    throw DpopErrors.invalidAccessToken('Access Token is not yet valid');
  }

  return payload;
}
