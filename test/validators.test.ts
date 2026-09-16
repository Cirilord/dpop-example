import { describe, expect, it } from 'vitest';

import { DpopError } from '../src/dpop/errors';
import { silentDpopLog } from '../src/dpop/logger';
import { validateAlg } from '../src/dpop/validate-alg';
import { accessTokenHash, validateAth } from '../src/dpop/validate-ath';
import { validateHtm } from '../src/dpop/validate-htm';
import { validateIat } from '../src/dpop/validate-iat';
import { validateJtiPresent } from '../src/dpop/validate-jti';
import { validateJwk } from '../src/dpop/validate-jwk';
import { validateTyp } from '../src/dpop/validate-typ';

describe('individual DPoP claim validators', () => {
  it('accepts typ dpop+jwt only', () => {
    expect(() => validateTyp('dpop+jwt', silentDpopLog)).not.toThrow();
    expect(() => validateTyp('JWT', silentDpopLog)).toThrow(DpopError);
  });

  it('accepts alg ES256 only', () => {
    expect(() => validateAlg('ES256', silentDpopLog)).not.toThrow();
    expect(() => validateAlg('none', silentDpopLog)).toThrow(DpopError);
    expect(() => validateAlg('RS256', silentDpopLog)).toThrow(DpopError);
  });

  it('rejects JWKs that contain private parameters or the wrong curve', () => {
    expect(() =>
      validateJwk({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }, silentDpopLog)
    ).not.toThrow();
    expect(() =>
      validateJwk({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', d: 'private' }, silentDpopLog)
    ).toThrow(DpopError);
    expect(() => validateJwk({ kty: 'oct', k: 'secret' }, silentDpopLog)).toThrow(DpopError);
  });

  it('compares HTM case-insensitively against the real method', () => {
    expect(() => validateHtm('GET', 'get', silentDpopLog)).not.toThrow();
    expect(() => validateHtm('POST', 'GET', silentDpopLog)).toThrow(DpopError);
  });

  it('accepts iat within ±60 seconds', () => {
    const now = 1_700_000_000;
    expect(() => validateIat(now - 60, 60, silentDpopLog, now)).not.toThrow();
    expect(() => validateIat(now + 60, 60, silentDpopLog, now)).not.toThrow();
    expect(() => validateIat(now - 61, 60, silentDpopLog, now)).toThrow(DpopError);
  });

  it('requires a non-empty jti', () => {
    expect(validateJtiPresent('abc', silentDpopLog)).toBe('abc');
    expect(() => validateJtiPresent('', silentDpopLog)).toThrow(DpopError);
    expect(() => validateJtiPresent(undefined, silentDpopLog)).toThrow(DpopError);
  });

  it('computes ATH as base64url(SHA-256(access_token))', () => {
    const token = 'access-token-value';
    const ath = accessTokenHash(token);
    expect(() => validateAth(ath, token, silentDpopLog)).not.toThrow();
    expect(() => validateAth(ath, 'other-token', silentDpopLog)).toThrow(DpopError);
  });
});
