/**
 * Machine-readable error codes used in JSON bodies.
 * HTTP status is always 401 for DPoP/authorization failures.
 */
export class DpopError extends Error {
  readonly error: string;

  constructor(error: string, message: string) {
    super(message);
    this.name = 'DpopError';
    this.error = error;
  }
}

export const DpopErrors = {
  invalidAuthorizationScheme: () =>
    new DpopError('invalid_request', 'Authorization scheme must be DPoP, not Bearer'),
  missingDpop: () => new DpopError('invalid_dpop_proof', 'Missing DPoP header'),
  multipleDpop: () => new DpopError('invalid_dpop_proof', 'Multiple DPoP headers are not allowed'),
  malformed: () => new DpopError('invalid_dpop_proof', 'Malformed DPoP proof'),
  invalidTyp: () => new DpopError('invalid_dpop_proof', 'Invalid DPoP typ'),
  invalidAlgorithm: () => new DpopError('invalid_dpop_proof', 'Invalid DPoP algorithm'),
  invalidJwk: (reason: string) => new DpopError('invalid_dpop_proof', reason),
  invalidSignature: () => new DpopError('invalid_dpop_proof', 'Invalid DPoP signature'),
  invalidHtm: () => new DpopError('invalid_dpop_proof', 'Invalid HTM'),
  invalidHtu: () => new DpopError('invalid_dpop_proof', 'Invalid HTU'),
  expired: () => new DpopError('invalid_dpop_proof', 'DPoP proof expired'),
  missingJti: () => new DpopError('invalid_dpop_proof', 'Missing JTI'),
  replay: () => new DpopError('dpop_replay_detected', 'DPoP replay detected'),
  missingAth: () => new DpopError('invalid_dpop_proof', 'Missing ATH'),
  invalidAth: () => new DpopError('invalid_ath', 'Invalid ATH'),
  invalidAccessToken: (reason: string) => new DpopError('invalid_token', reason),
  missingCnf: () => new DpopError('dpop_key_mismatch', 'Access Token is missing cnf.jkt'),
  keyMismatch: () => new DpopError('dpop_key_mismatch', 'public key does not match Access Token'),
};
