import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

/**
 * RFC 9449: `htm` is the HTTP method of the request to which the
 * proof is bound, in uppercase (GET, POST, ...).
 */
export function validateHtm(proofHtm: unknown, requestMethod: string, log: DpopLog): void {
  const expected = requestMethod.toUpperCase();
  const received = typeof proofHtm === 'string' ? proofHtm.toUpperCase() : '';

  if (received !== expected) {
    log.fail('HTM', `expected: ${expected}\nreceived: ${String(proofHtm)}`);
    throw DpopErrors.invalidHtm();
  }

  log.ok('HTM', `expected: ${expected}\nreceived: ${received}`);
}
