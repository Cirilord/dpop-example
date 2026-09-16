import { describe, expect, it } from 'vitest';

import { DpopError } from '../src/dpop/errors';
import { silentDpopLog } from '../src/dpop/logger';
import { normalizeHttpUri, validateHtu } from '../src/dpop/validate-htu';

describe('normalizeHttpUri', () => {
  it('strips query and fragment', () => {
    expect(normalizeHttpUri('http://localhost:3000/api/protected?x=1#frag')).toBe(
      'http://localhost:3000/api/protected'
    );
  });

  it('omits default HTTP and HTTPS ports', () => {
    expect(normalizeHttpUri('http://localhost:80/api')).toBe('http://localhost/api');
    expect(normalizeHttpUri('https://example.com:443/api')).toBe('https://example.com/api');
  });

  it('keeps non-default ports', () => {
    expect(normalizeHttpUri('http://localhost:3000/api')).toBe('http://localhost:3000/api');
  });

  it('lowercases scheme and host, preserves path case', () => {
    expect(normalizeHttpUri('HTTP://LocalHost:3000/Api/Protected')).toBe(
      'http://localhost:3000/Api/Protected'
    );
  });
});

describe('validateHtu', () => {
  it('accepts equivalent URIs after normalization', () => {
    expect(() =>
      validateHtu(
        'http://localhost:3000/api/protected?unused=1',
        'http://localhost:3000/api/protected',
        silentDpopLog
      )
    ).not.toThrow();
  });

  it('rejects a different path', () => {
    expect(() =>
      validateHtu(
        'http://localhost:3000/api/other',
        'http://localhost:3000/api/protected',
        silentDpopLog
      )
    ).toThrow(DpopError);
  });
});
