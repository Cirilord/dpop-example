import { decodeProtectedHeader } from 'jose';
import type { JWK, JWTVerifyGetKey } from 'jose';

import { DpopError, DpopErrors } from './errors';
import type { DpopLog } from './logger';
import { validateAccessToken } from './validate-access-token';
import { validateAlg } from './validate-alg';
import { validateAth } from './validate-ath';
import { jwkThumbprint, validateCnf } from './validate-cnf';
import { validateHtm } from './validate-htm';
import { validateHtu } from './validate-htu';
import { validateIat } from './validate-iat';
import { validateJtiPresent, validateJtiUnique } from './validate-jti';
import type { ReplayStore } from './validate-jti';
import { validateJwk } from './validate-jwk';
import { validateSignature } from './validate-signature';
import { validateTyp } from './validate-typ';

export interface VerifyDpopRequestInput {
  method: string;
  httpUri: string;
  authorizationHeader?: string;
  dpopHeader?: string | string[];
  accessTokenJwks: JWTVerifyGetKey;
  issuer: string;
  audience: string;
  replayStore: ReplayStore;
  iatToleranceSeconds: number;
  jtiTtlSeconds: number;
  log: DpopLog;
  nowSeconds?: number;
}

function parseDpopAuthorization(header: string | undefined): string {
  if (!header) {
    throw DpopErrors.invalidAuthorizationScheme();
  }
  const [scheme, token, ...rest] = header.split(' ');
  if (scheme.toLowerCase() !== 'dpop' || !token || rest.length > 0) {
    throw DpopErrors.invalidAuthorizationScheme();
  }
  return token;
}

function parseDpopHeader(header: string | string[] | undefined): string {
  if (Array.isArray(header)) {
    throw DpopErrors.multipleDpop();
  }
  if (!header) {
    throw DpopErrors.missingDpop();
  }
  return header;
}

function decodeDpopHeader(dpopJwt: string, log: DpopLog) {
  try {
    return decodeProtectedHeader(dpopJwt);
  } catch {
    log.fail('DPoP', 'malformed compact JWT');
    throw DpopErrors.malformed();
  }
}

function decodePayload(bytes: Uint8Array): Record<string, unknown> {
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
  } catch {
    throw DpopErrors.malformed();
  }
}

/**
 * Full Resource Server validation of a sender-constrained request:
 *
 *   Authorization: DPoP <access_token>
 *   DPoP: <proof>
 *
 * Each step is a separate function so the protocol can be read
 * top-to-bottom and tested in isolation.
 */
export async function verifyDpopRequest(input: VerifyDpopRequestInput): Promise<{
  accessToken: string;
  accessTokenPayload: Record<string, unknown>;
  dpopPayload: Record<string, unknown>;
  jkt: string;
  publicJwk: JWK;
}> {
  const { log, nowSeconds } = input;
  log.start();

  try {
    const accessToken = parseDpopAuthorization(input.authorizationHeader);
    const dpopJwt = parseDpopHeader(input.dpopHeader);

    const accessTokenPayload = await validateAccessToken(
      accessToken,
      input.accessTokenJwks,
      input.issuer,
      input.audience,
      log,
      nowSeconds
    );

    const header = decodeDpopHeader(dpopJwt, log);
    validateTyp(header.typ, log);
    validateAlg(header.alg, log);
    const publicJwk = validateJwk(header.jwk, log);

    const payloadBytes = await validateSignature(dpopJwt, publicJwk, log);
    const dpopPayload = decodePayload(payloadBytes);

    validateHtm(dpopPayload.htm, input.method, log);
    validateHtu(dpopPayload.htu, input.httpUri, log);
    validateIat(dpopPayload.iat, input.iatToleranceSeconds, log, nowSeconds);

    const jti = validateJtiPresent(dpopPayload.jti, log);
    const jkt = await jwkThumbprint(publicJwk);
    await validateJtiUnique(input.replayStore, jkt, jti, input.jtiTtlSeconds, log);

    validateAth(dpopPayload.ath, accessToken, log);
    validateCnf(accessTokenPayload, jkt, log);

    log.finish('DPoP validation succeeded');
    return {
      accessToken,
      accessTokenPayload,
      dpopPayload,
      jkt,
      publicJwk,
    };
  } catch (error) {
    if (error instanceof DpopError) {
      log.finish(`DPoP validation failed:\n${error.message}`);
    }
    throw error;
  }
}
