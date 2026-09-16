import { compactVerify, importJWK } from 'jose';
import type { JWK } from 'jose';

import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

/**
 * Cryptographic proof that the sender holds the private key
 * corresponding to `header.jwk`.
 *
 * Extracting the JWK is not enough: anyone can copy a public key
 * into a JWT header. The signature binds the payload (htu, htm, jti,
 * iat, ath) to that key.
 */
export async function validateSignature(
  dpopJwt: string,
  publicJwk: JWK,
  log: DpopLog
): Promise<Uint8Array> {
  try {
    const key = await importJWK(publicJwk, 'ES256');
    const { payload } = await compactVerify(dpopJwt, key, {
      algorithms: ['ES256'],
    });
    log.ok('DPoP signature');
    return payload;
  } catch {
    log.fail('DPoP signature', 'compactVerify rejected the proof');
    throw DpopErrors.invalidSignature();
  }
}
