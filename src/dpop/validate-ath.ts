import { createHash, timingSafeEqual } from 'node:crypto';

import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

/**
 * ATH binds this DPoP proof to the Access Token used
 * in this specific request.
 *
 * stealing only this DPoP proof does not allow it to
 * be used with another Access Token.
 *
 * RFC 9449: ath = base64url( SHA-256( access_token ) )
 * The access token itself is never placed inside the proof.
 */
export function accessTokenHash(accessToken: string): string {
  const digest = createHash('sha256').update(accessToken, 'ascii').digest();
  return digest.toString('base64url');
}

function timingSafeEqualString(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

export function validateAth(proofAth: unknown, accessToken: string, log: DpopLog): void {
  if (typeof proofAth !== 'string' || proofAth.length === 0) {
    log.fail('ATH', 'ath claim is missing');
    throw DpopErrors.missingAth();
  }

  const expected = accessTokenHash(accessToken);
  if (!timingSafeEqualString(proofAth, expected)) {
    log.fail('ATH', `expected: ${expected}\nreceived: ${proofAth}`);
    throw DpopErrors.invalidAth();
  }

  log.ok('ATH', `expected: ${expected}\nreceived: ${proofAth}`);
}
