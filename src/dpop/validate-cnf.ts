import { calculateJwkThumbprint } from 'jose';
import type { JWK } from 'jose';

import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

/**
 * CNF binds the Access Token to the public key whose
 * corresponding private key must sign every DPoP proof.
 *
 * Access Token
 *        |
 *        | cnf.jkt
 *        v
 * Public Key A
 *
 * DPoP Proof
 *        |
 *        | signed by
 *        v
 * Private Key A
 *
 * Possessing the Access Token alone is not enough: the caller must
 * also possess the private key whose thumbprint is in cnf.jkt.
 */
export async function jwkThumbprint(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk, 'sha256');
}

function extractJkt(payload: Record<string, unknown>): string {
  const cnf = payload.cnf;
  if (!cnf || typeof cnf !== 'object' || Array.isArray(cnf)) {
    throw DpopErrors.missingCnf();
  }
  const jkt = (cnf as { jkt?: unknown }).jkt;
  if (typeof jkt !== 'string' || jkt.length === 0) {
    throw DpopErrors.missingCnf();
  }
  return jkt;
}

export function validateCnf(
  accessTokenPayload: Record<string, unknown>,
  proofJkt: string,
  log: DpopLog
): void {
  let tokenJkt: string;
  try {
    tokenJkt = extractJkt(accessTokenPayload);
  } catch (error) {
    log.fail('CNF', 'Access Token is missing cnf.jkt');
    throw error;
  }

  if (tokenJkt !== proofJkt) {
    log.fail(
      'CNF',
      `token jkt:\n${tokenJkt}\n\nproof jkt:\n${proofJkt}\n\nDPoP validation failed:\npublic key does not match Access Token`
    );
    throw DpopErrors.keyMismatch();
  }

  log.ok('CNF', `token jkt:    ${tokenJkt}\nproof jkt:    ${proofJkt}`);
}
