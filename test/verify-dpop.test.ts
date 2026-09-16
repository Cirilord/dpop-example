import { generateSecret, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  createDpopKey,
  MemoryReplayStore,
  NOW,
  RESOURCE_URI,
  signAccessToken,
  signDpopProof,
  validPair,
  verify,
} from './helpers';
import { accessTokenHash } from '../src/dpop/validate-ath';

describe('verifyDpopRequest', () => {
  it('accepts a valid DPoP request', async () => {
    const pair = await validPair();
    const result = await verify(pair);
    expect(result.jkt).toBe(pair.dpop.jkt);
    expect(result.accessTokenPayload.sub).toBe('alice');
  });

  it('rejects an invalid DPoP signature', async () => {
    const pair = await validPair();
    const [header, payload] = pair.proof.split('.');
    const tampered = `${header}.${payload}.dGFtcGVyZWQ`;

    await expect(verify({ ...pair, proof: tampered })).rejects.toMatchObject({
      error: 'invalid_dpop_proof',
      message: 'Invalid DPoP signature',
    });
  });

  it('rejects an invalid typ', async () => {
    const pair = await validPair();
    const proof = await signDpopProof({
      privateKey: pair.dpop.privateKey,
      publicJwk: pair.dpop.publicJwk,
      typ: 'JWT',
      payload: {
        htm: 'GET',
        htu: RESOURCE_URI,
        iat: NOW,
        jti: 'jti-typ',
        ath: accessTokenHash(pair.accessToken),
      },
    });

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      message: 'Invalid DPoP typ',
    });
  });

  it('rejects an invalid algorithm', async () => {
    const pair = await validPair();
    const secret = await generateSecret('HS256');
    const proof = await new SignJWT({
      htm: 'GET',
      htu: RESOURCE_URI,
      iat: NOW,
      jti: 'jti-alg',
      ath: accessTokenHash(pair.accessToken),
    })
      .setProtectedHeader({
        typ: 'dpop+jwt',
        alg: 'HS256',
        jwk: pair.dpop.publicJwk,
      })
      .sign(secret);

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      message: 'Invalid DPoP algorithm',
    });
  });

  it('never accepts alg none', async () => {
    const pair = await validPair();
    const header = Buffer.from(
      JSON.stringify({
        typ: 'dpop+jwt',
        alg: 'none',
        jwk: pair.dpop.publicJwk,
      })
    ).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        htm: 'GET',
        htu: RESOURCE_URI,
        iat: NOW,
        jti: 'jti-none',
        ath: accessTokenHash(pair.accessToken),
      })
    ).toString('base64url');
    const proof = `${header}.${payload}.`;

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      message: 'Invalid DPoP algorithm',
    });
  });

  it('rejects an invalid HTM', async () => {
    const pair = await validPair();
    const proof = await signDpopProof({
      privateKey: pair.dpop.privateKey,
      publicJwk: pair.dpop.publicJwk,
      payload: {
        htm: 'POST',
        htu: RESOURCE_URI,
        iat: NOW,
        jti: 'jti-htm',
        ath: accessTokenHash(pair.accessToken),
      },
    });

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      message: 'Invalid HTM',
    });
  });

  it('rejects an invalid HTU', async () => {
    const pair = await validPair();
    const proof = await signDpopProof({
      privateKey: pair.dpop.privateKey,
      publicJwk: pair.dpop.publicJwk,
      payload: {
        htm: 'GET',
        htu: 'http://localhost:3000/api/other',
        iat: NOW,
        jti: 'jti-htu',
        ath: accessTokenHash(pair.accessToken),
      },
    });

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      message: 'Invalid HTU',
    });
  });

  it('rejects an expired IAT', async () => {
    const pair = await validPair();
    const proof = await signDpopProof({
      privateKey: pair.dpop.privateKey,
      publicJwk: pair.dpop.publicJwk,
      payload: {
        htm: 'GET',
        htu: RESOURCE_URI,
        iat: NOW - 120,
        jti: 'jti-iat',
        ath: accessTokenHash(pair.accessToken),
      },
    });

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      message: 'DPoP proof expired',
    });
  });

  it('rejects a missing JTI', async () => {
    const pair = await validPair();
    const proof = await signDpopProof({
      privateKey: pair.dpop.privateKey,
      publicJwk: pair.dpop.publicJwk,
      payload: {
        htm: 'GET',
        htu: RESOURCE_URI,
        iat: NOW,
        ath: accessTokenHash(pair.accessToken),
      },
    });

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      message: 'Missing JTI',
    });
  });

  it('rejects a replayed JTI', async () => {
    const pair = await validPair();
    const replayStore = new MemoryReplayStore();

    await verify({ ...pair, replayStore });
    await expect(verify({ ...pair, replayStore })).rejects.toMatchObject({
      error: 'dpop_replay_detected',
      message: 'DPoP replay detected',
    });
  });

  it('rejects a missing ATH', async () => {
    const pair = await validPair();
    const proof = await signDpopProof({
      privateKey: pair.dpop.privateKey,
      publicJwk: pair.dpop.publicJwk,
      payload: {
        htm: 'GET',
        htu: RESOURCE_URI,
        iat: NOW,
        jti: 'jti-no-ath',
      },
    });

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      message: 'Missing ATH',
    });
  });

  it('rejects an invalid ATH', async () => {
    const pair = await validPair();
    const proof = await signDpopProof({
      privateKey: pair.dpop.privateKey,
      publicJwk: pair.dpop.publicJwk,
      payload: {
        htm: 'GET',
        htu: RESOURCE_URI,
        iat: NOW,
        jti: 'jti-bad-ath',
        ath: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
    });

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      error: 'invalid_ath',
      message: 'Invalid ATH',
    });
  });

  it('rejects a missing CNF', async () => {
    const pair = await validPair();
    const accessToken = await signAccessToken(pair.as.privateKey, {
      sub: 'alice',
    });
    const proof = await signDpopProof({
      privateKey: pair.dpop.privateKey,
      publicJwk: pair.dpop.publicJwk,
      payload: {
        htm: 'GET',
        htu: RESOURCE_URI,
        iat: NOW,
        jti: 'jti-no-cnf',
        ath: accessTokenHash(accessToken),
      },
    });

    await expect(verify({ ...pair, accessToken, proof })).rejects.toMatchObject({
      error: 'dpop_key_mismatch',
    });
  });

  it('rejects a CNF thumbprint mismatch', async () => {
    const pair = await validPair();
    const attacker = await createDpopKey();
    const proof = await signDpopProof({
      privateKey: attacker.privateKey,
      publicJwk: attacker.publicJwk,
      payload: {
        htm: 'GET',
        htu: RESOURCE_URI,
        iat: NOW,
        jti: 'jti-stolen',
        ath: accessTokenHash(pair.accessToken),
      },
    });

    await expect(verify({ ...pair, proof })).rejects.toMatchObject({
      error: 'dpop_key_mismatch',
    });
  });

  it('rejects Authorization Bearer for a DPoP-bound token', async () => {
    const pair = await validPair();
    await expect(
      verify({
        ...pair,
        authorizationHeader: `Bearer ${pair.accessToken}`,
      })
    ).rejects.toMatchObject({
      error: 'invalid_request',
    });
  });
});
