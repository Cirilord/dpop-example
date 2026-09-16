import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

/**
 * RFC 9449: the JOSE header `typ` MUST be `dpop+jwt`.
 * This distinguishes a DPoP proof from a regular JWT access token.
 */
export function validateTyp(typ: unknown, log: DpopLog): void {
  if (typ !== 'dpop+jwt') {
    log.fail('typ', `expected: dpop+jwt\nreceived: ${String(typ)}`);
    throw DpopErrors.invalidTyp();
  }
  log.ok('typ = dpop+jwt');
}
