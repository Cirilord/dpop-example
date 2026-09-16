import { calculateThumbprint, generateKeyPair, generateProof } from 'dpop';
import type { KeyPair } from 'dpop';
import type { JWK } from 'jose';

import { normalizeHttpUri } from '../src/dpop/validate-htu';

export type DpopKeyMaterial = KeyPair & {
  publicJwk: JWK;
  jkt: string;
};

export type TokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
};

export type DpopClientConfig = {
  tokenEndpoint: string;
  clientId: string;
  username: string;
  password: string;
};

/**
 * The private key stays in this process and is not extractable.
 * Web Crypto still marks the public key extractable, which `dpop`
 * needs in order to put it in the JWT `jwk` header.
 */
export async function generateDpopKeys(): Promise<DpopKeyMaterial> {
  const keypair = await generateKeyPair('ES256', { extractable: false });
  const exported = await crypto.subtle.exportKey('jwk', keypair.publicKey);
  const publicJwk: JWK = {
    kty: 'EC',
    crv: exported.crv,
    x: exported.x,
    y: exported.y,
  };

  /**
   * RFC 7638 JWK Thumbprint — same value Keycloak later embeds in
   * access_token.cnf.jkt.
   */
  const jkt = await calculateThumbprint(keypair.publicKey);

  return {
    ...keypair,
    publicJwk,
    jkt,
  };
}

export async function createDpopProof(params: {
  url: string;
  method: string;
  accessToken?: string;
  keypair: KeyPair;
}): Promise<string> {
  /**
   * `dpop.generateProof` builds typ=dpop+jwt, embeds the public JWK,
   * and sets htu / htm / iat / jti.
   *
   * nonce is omitted: this demo does not implement DPoP-Nonce.
   *
   * There is no ATH unless `accessToken` is passed, because an Access
   * Token does not exist yet at the Token Endpoint. When it is passed,
   * the library sets ath = base64url(SHA-256(access_token)). The token
   * itself is never placed inside the proof.
   */
  return generateProof(
    params.keypair,
    normalizeHttpUri(params.url),
    params.method.toUpperCase(),
    undefined,
    params.accessToken
  );
}

export async function requestAccessToken(
  config: DpopClientConfig,
  keys: DpopKeyMaterial
): Promise<{ token: TokenResponse; dpopProof: string }> {
  const dpopProof = await createDpopProof({
    url: config.tokenEndpoint,
    method: 'POST',
    keypair: keys,
  });

  const response = await fetch(config.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'DPoP': dpopProof,
    },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: config.clientId,
      username: config.username,
      password: config.password,
      scope: 'openid',
    }),
  });

  const json: unknown = await response.json();
  if (!response.ok) {
    throw new Error(`Token request failed (${response.status}): ${JSON.stringify(json, null, 2)}`);
  }

  return { token: json as TokenResponse, dpopProof };
}

export async function callProtectedApi(
  protectedUrl: string,
  accessToken: string,
  dpopProof: string
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(protectedUrl, {
    method: 'GET',
    headers: {
      Authorization: `DPoP ${accessToken}`,
      DPoP: dpopProof,
    },
  });
  const body: unknown = await response.json().catch(() => ({}));
  return { status: response.status, body };
}
