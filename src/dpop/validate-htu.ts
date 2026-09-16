import { DpopErrors } from './errors';
import type { DpopLog } from './logger';

function isDefaultPort(scheme: string, port: string): boolean {
  return (scheme === 'http' && port === '80') || (scheme === 'https' && port === '443');
}

/**
 * Normalize an HTTP URI the way DPoP comparison requires.
 *
 * RFC 9449 §4.2: `htu` is the HTTP URI without query and fragment.
 * Scheme and host are compared case-insensitively. Default ports are
 * omitted. The path is compared as-is (case-sensitive).
 *
 * This is intentionally NOT `proof.htu === request.url`:
 *   - `request.url` in most frameworks is only the path + query
 *   - query strings must be ignored
 *   - `http://localhost:80/api` and `http://localhost/api` are the same
 *   - reverse proxies may change scheme/host/port (see README)
 */
export function normalizeHttpUri(input: string): string {
  const url = new URL(input);
  const scheme = url.protocol.replace(/:$/, '').toLowerCase();
  const host = url.hostname.toLowerCase();
  const port = url.port && !isDefaultPort(scheme, url.port) ? `:${url.port}` : '';
  const path = url.pathname || '/';
  return `${scheme}://${host}${port}${path}`;
}

export function buildResourceUri(publicBaseUrl: string, requestUrl: string): string {
  return normalizeHttpUri(new URL(requestUrl, `${publicBaseUrl}/`).href);
}

export function validateHtu(proofHtu: unknown, requestUri: string, log: DpopLog): void {
  if (typeof proofHtu !== 'string' || proofHtu.length === 0) {
    log.fail('HTU', 'htu claim is missing');
    throw DpopErrors.invalidHtu();
  }

  const expected = normalizeHttpUri(requestUri);
  let received: string;
  try {
    received = normalizeHttpUri(proofHtu);
  } catch {
    log.fail('HTU', `htu is not a valid URI: ${proofHtu}`);
    throw DpopErrors.invalidHtu();
  }

  if (received !== expected) {
    log.fail('HTU', `expected: ${expected}\nreceived: ${received}`);
    throw DpopErrors.invalidHtu();
  }

  log.ok('HTU', `expected: ${expected}\nreceived: ${received}`);
}
