import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

/**
 * RFC 9449: `iat` is the time at which the proof was created.
 * A small clock-skew window is accepted; everything else is treated
 * as an expired (or not-yet-valid) proof.
 */
export function validateIat(
  iat: unknown,
  toleranceSeconds: number,
  log: DpopLog,
  nowSeconds = Math.floor(Date.now() / 1000)
): void {
  if (typeof iat !== 'number' || !Number.isFinite(iat)) {
    log.fail('IAT', 'iat claim is missing or not a number');
    throw DpopErrors.expired();
  }

  const age = nowSeconds - iat;
  if (Math.abs(age) > toleranceSeconds) {
    log.fail('IAT', `age: ${age}s\ntolerance: ±${toleranceSeconds}s`);
    throw DpopErrors.expired();
  }

  log.ok('IAT', `age: ${age}s`);
}
