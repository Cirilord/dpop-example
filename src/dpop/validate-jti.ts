import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

export interface ReplayStore {
  /**
   * Records `jti` for this public-key thumbprint.
   * Returns true on first use, false if the key already exists.
   */
  consumeOnce(jkt: string, jti: string, ttlSeconds: number): Promise<boolean>;
}

export function validateJtiPresent(jti: unknown, log: DpopLog): string {
  if (typeof jti !== 'string' || jti.length === 0) {
    log.fail('JTI', 'jti claim is missing');
    throw DpopErrors.missingJti();
  }
  log.ok('JTI', jti);
  return jti;
}

/**
 * Replay protection: the same (key, jti) pair can only be used once
 * within the proof lifetime.
 *
 * Redis: SET dpop:jti:<jkt>:<jti> 1 NX EX <ttl>
 *   NX -> only if the key does not exist
 *   first request: OK  -> MISS -> accept
 *   replay:        null -> HIT  -> reject
 */
export async function validateJtiUnique(
  replayStore: ReplayStore,
  jkt: string,
  jti: string,
  ttlSeconds: number,
  log: DpopLog
): Promise<void> {
  const firstUse = await replayStore.consumeOnce(jkt, jti, ttlSeconds);
  if (!firstUse) {
    log.fail('Replay protection', `Redis: HIT\njti: ${jti}`);
    throw DpopErrors.replay();
  }
  log.ok('Replay protection', `Redis: MISS\njti: ${jti}`);
}
