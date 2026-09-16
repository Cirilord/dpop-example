import { config as loadEnv } from 'dotenv';
import { decodeJwt, decodeProtectedHeader } from 'jose';

import {
  callProtectedApi,
  createDpopProof,
  generateDpopKeys,
  requestAccessToken,
} from './dpop-client';

loadEnv({ quiet: true });

const KEYCLOAK_URL = process.env.KEYCLOAK_URL ?? 'http://localhost:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM ?? 'dpop-demo';

const client = {
  tokenEndpoint: `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`,
  protectedUrl: `${process.env.RESOURCE_SERVER_PUBLIC_URL ?? 'http://localhost:3000'}/api/protected`,
  clientId: process.env.KEYCLOAK_CLIENT_ID ?? 'dpop-client',
  username: process.env.KEYCLOAK_USERNAME ?? 'alice',
  password: process.env.KEYCLOAK_PASSWORD ?? 'alice',
};

function section(title: string): void {
  console.log(`\n=== ${title} ===\n`);
}

function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

section('1. Generate ES256 P-256 key pair');
const keys = await generateDpopKeys();
console.log('Client JWK thumbprint (jkt):', keys.jkt);
console.log('Public JWK:', pretty(keys.publicJwk));

section('2. Login (DPoP proof without ath)');
const { token, dpopProof: loginProof } = await requestAccessToken(client, keys);
const tokenPayload = decodeJwt(token.access_token) as {
  cnf?: { jkt?: string };
};

console.log('token_type:', token.token_type);
console.log('Access Token:', token.access_token);
console.log('Decoded Access Token payload:', pretty(tokenPayload));
console.log('cnf.jkt:', tokenPayload.cnf?.jkt ?? '(missing)');
console.log('Thumbprints match:', keys.jkt === tokenPayload.cnf?.jkt ? 'yes' : 'no');
console.log('Login DPoP proof:', loginProof);
console.log(
  'Decoded login proof (no ath):',
  pretty({
    header: decodeProtectedHeader(loginProof),
    payload: decodeJwt(loginProof),
  })
);

section('3. GET /api/protected (DPoP proof with ath)');
const apiProof = await createDpopProof({
  url: client.protectedUrl,
  method: 'GET',
  accessToken: token.access_token,
  keypair: keys,
});
const first = await callProtectedApi(client.protectedUrl, token.access_token, apiProof);
console.log('API DPoP proof:', apiProof);
console.log(
  'Decoded API proof (with ath):',
  pretty({
    header: decodeProtectedHeader(apiProof),
    payload: decodeJwt(apiProof),
  })
);
console.log(`Response ${first.status}:`, pretty(first.body));
if (first.status !== 200) {
  throw new Error('Expected the first protected request to succeed');
}

section('4. Replay last request (same token + same DPoP / jti)');
const replay = await callProtectedApi(client.protectedUrl, token.access_token, apiProof);
console.log(`Response ${replay.status}:`, pretty(replay.body));
if (replay.status !== 401) {
  throw new Error('Expected replay to be rejected');
}

section('5. Stolen Access Token (token from Key A, DPoP signed by Key B)');
const attacker = await generateDpopKeys();
const stolenProof = await createDpopProof({
  url: client.protectedUrl,
  method: 'GET',
  accessToken: token.access_token,
  keypair: attacker,
});
const stolen = await callProtectedApi(client.protectedUrl, token.access_token, stolenProof);
console.log('Attacker jkt:', attacker.jkt);
console.log(`Response ${stolen.status}:`, pretty(stolen.body));
if (stolen.status !== 401) {
  throw new Error('Expected a DPoP signed with a different key to be rejected');
}

section('Done');
console.log('Valid request: 200');
console.log('Replay:        401');
console.log('Stolen token:  401');
