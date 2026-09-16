import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

/**
 * This demo only accepts ES256 (ECDSA P-256).
 *
 * Rejecting `none` and unexpected algorithms is mandatory:
 * the `alg` value in the header is attacker-controlled until the
 * signature is verified, so we whitelist first.
 */
export function validateAlg(alg: unknown, log: DpopLog): void {
  if (alg !== 'ES256') {
    log.fail('alg', `expected: ES256\nreceived: ${String(alg)}`);
    throw DpopErrors.invalidAlgorithm();
  }
  log.ok('alg = ES256');
}
