// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { describe, expect, test } from 'vitest';

import { act, TOKEN_TYPES } from '../src/index.js';
const {
    ACT,
    ACT_TOKEN_TYPE,
    ACTTokenChallenge,
    ACTTokenRequest,
    ACTTokenResponse,
    ACTToken,
    Client,
    Issuer,
    NoCredentialError,
    InsufficientBalanceError,
    CredentialInUseError,
} = act;

// =============================================================================
// Token Type Entry
// =============================================================================

describe('ACT Token Type', () => {
    test('has correct value', () => {
        expect(ACT.value).toBe(0xe5ad);
        expect(ACT_TOKEN_TYPE).toBe(0xe5ad);
    });

    test('is registered in TOKEN_TYPES', () => {
        expect(TOKEN_TYPES.ACT).toBe(ACT);
    });

    test('has correct properties', () => {
        expect(ACT.name).toBe('ACT (Ristretto255)');
        expect(ACT.Nk).toBe(0);
        expect(ACT.Nid).toBe(32);
        expect(ACT.publicVerifiable).toBe(false);
        expect(ACT.publicMetadata).toBe(false);
        expect(ACT.privateMetadata).toBe(false);
    });
});

// =============================================================================
// Serialization Roundtrips
// =============================================================================

describe('ACTTokenChallenge', () => {
    test('serializes and deserializes with full data', () => {
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            crypto.getRandomValues(new Uint8Array(32)),
            ['origin1.example.com', 'origin2.example.com'],
            crypto.getRandomValues(new Uint8Array(32)),
        );

        const bytes = challenge.serialize();
        const parsed = ACTTokenChallenge.deserialize(bytes);

        expect(parsed.tokenType).toBe(ACT.value);
        expect(parsed.issuerName).toBe(challenge.issuerName);
        expect(parsed.redemptionContext).toEqual(challenge.redemptionContext);
        expect(parsed.originInfo).toEqual(challenge.originInfo);
        expect(parsed.credentialContext).toEqual(challenge.credentialContext);
    });

    test('serializes and deserializes with empty optional fields', () => {
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            new Uint8Array(0), // empty redemption context
            undefined, // no origin info
            new Uint8Array(0), // empty credential context
        );

        const bytes = challenge.serialize();
        const parsed = ACTTokenChallenge.deserialize(bytes);

        expect(parsed.redemptionContext.length).toBe(0);
        expect(parsed.originInfo).toBeUndefined();
        expect(parsed.credentialContext.length).toBe(0);
    });

    test('rejects invalid credential context length', () => {
        expect(
            () =>
                new ACTTokenChallenge(
                    'issuer.example.com',
                    new Uint8Array(32),
                    undefined,
                    new Uint8Array(16), // invalid: must be 0 or 32
                ),
        ).toThrow('invalid credentialContext size');
    });

    test('rejects wrong token type on deserialize', () => {
        const bytes = new Uint8Array(10);
        new DataView(bytes.buffer).setUint16(0, 0x0002); // BLIND_RSA token type

        expect(() => ACTTokenChallenge.deserialize(bytes)).toThrow('invalid token type');
    });
});

describe('ACTTokenRequest', () => {
    test('serializes and deserializes', () => {
        const request = new ACTTokenRequest(0x42, crypto.getRandomValues(new Uint8Array(100)));

        const bytes = request.serialize();
        const parsed = ACTTokenRequest.deserialize(bytes);

        expect(parsed.tokenType).toBe(ACT.value);
        expect(parsed.truncatedTokenKeyId).toBe(0x42);
        expect(parsed.encodedRequest).toEqual(request.encodedRequest);
    });

    test('rejects invalid truncatedTokenKeyId', () => {
        expect(() => new ACTTokenRequest(256, new Uint8Array(10))).toThrow(
            'truncatedTokenKeyId must be a single byte',
        );
        expect(() => new ACTTokenRequest(-1, new Uint8Array(10))).toThrow(
            'truncatedTokenKeyId must be a single byte',
        );
    });

    test('rejects wrong token type on deserialize', () => {
        const bytes = new Uint8Array(10);
        new DataView(bytes.buffer).setUint16(0, 0x0001); // VOPRF token type

        expect(() => ACTTokenRequest.deserialize(bytes)).toThrow('invalid token type');
    });
});

describe('ACTTokenResponse', () => {
    test('serializes and deserializes', () => {
        const response = new ACTTokenResponse(crypto.getRandomValues(new Uint8Array(200)));

        const bytes = response.serialize();
        const parsed = ACTTokenResponse.deserialize(bytes);

        expect(parsed.encodedResponse).toEqual(response.encodedResponse);
    });
});

describe('ACTToken', () => {
    test('serializes and deserializes', () => {
        const token = new ACTToken(
            crypto.getRandomValues(new Uint8Array(32)), // challengeDigest
            crypto.getRandomValues(new Uint8Array(32)), // issuerKeyId
            crypto.getRandomValues(new Uint8Array(500)), // spendProof
        );

        const bytes = token.serialize();
        const parsed = ACTToken.deserialize(bytes);

        expect(parsed.tokenType).toBe(ACT.value);
        expect(parsed.challengeDigest).toEqual(token.challengeDigest);
        expect(parsed.issuerKeyId).toEqual(token.issuerKeyId);
        expect(parsed.spendProof).toEqual(token.spendProof);
    });

    test('rejects invalid challengeDigest length', () => {
        expect(
            () =>
                new ACTToken(
                    new Uint8Array(16), // wrong size
                    new Uint8Array(32),
                    new Uint8Array(100),
                ),
        ).toThrow('challengeDigest must be 32 bytes');
    });

    test('rejects invalid issuerKeyId length', () => {
        expect(
            () =>
                new ACTToken(
                    new Uint8Array(32),
                    new Uint8Array(16), // wrong size
                    new Uint8Array(100),
                ),
        ).toThrow('issuerKeyId must be 32 bytes');
    });

    test('handles Uint8Array views correctly', () => {
        // Create a larger buffer and use views into it
        const largeBuffer = new ArrayBuffer(1000);
        const challengeDigest = new Uint8Array(largeBuffer, 100, 32);
        const issuerKeyId = new Uint8Array(largeBuffer, 200, 32);
        const spendProof = new Uint8Array(largeBuffer, 300, 100);

        // Fill with recognizable patterns
        challengeDigest.fill(0xaa);
        issuerKeyId.fill(0xbb);
        spendProof.fill(0xcc);

        const token = new ACTToken(challengeDigest, issuerKeyId, spendProof);
        const bytes = token.serialize();
        const parsed = ACTToken.deserialize(bytes);

        // Verify the serialized data is correct (not including extra buffer bytes)
        expect(parsed.challengeDigest.every((b) => b === 0xaa)).toBe(true);
        expect(parsed.issuerKeyId.every((b) => b === 0xbb)).toBe(true);
        expect(parsed.spendProof.every((b) => b === 0xcc)).toBe(true);
    });
});

// =============================================================================
// Full Flow Tests
// =============================================================================

// Helper to create 32-byte credential context from string
function makeCredentialContext(label: string): Uint8Array {
    const ctx = new Uint8Array(32);
    const bytes = new TextEncoder().encode(label);
    ctx.set(bytes.subarray(0, Math.min(bytes.length, 32)));
    return ctx;
}

describe('ACT Full Flow', () => {
    const domainSeparator = new TextEncoder().encode('ACT-v1:test:api:dev');
    const L = 16; // Small L for fast tests

    test('issuance flow', async () => {
        const issuer = Issuer.create(domainSeparator, L);
        const client = Client.create(domainSeparator, L);

        const credentialContext = makeCredentialContext('test-context');
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            crypto.getRandomValues(new Uint8Array(32)),
            ['origin.example.com'],
            credentialContext,
        );

        // Client creates token request
        const tokReq = await client.createTokenRequest(challenge, issuer.publicKeyBytes);
        expect(tokReq.tokenType).toBe(ACT.value);

        // Test serialization roundtrip
        const tokReqBytes = tokReq.serialize();
        const tokReqParsed = ACTTokenRequest.deserialize(tokReqBytes);
        expect(tokReqParsed.encodedRequest).toEqual(tokReq.encodedRequest);

        // Issuer processes request
        const tokResBytes = issuer.issue(tokReq.encodedRequest, 100n, challenge);

        // Client finalizes credential
        const tokRes = ACTTokenResponse.deserialize(
            new Uint8Array([
                ...new Uint8Array(new Uint16Array([tokResBytes.length]).buffer),
                ...tokResBytes,
            ]),
        );
        const credInfo = client.finalizeCredential(tokRes, issuer.publicKey);

        expect(credInfo.balance).toBe(100n);
        expect(client.hasCredential(challenge)).toBe(true);
        expect(client.getBalance(challenge)).toBe(100n);
    });

    test('spend and refund flow', async () => {
        const issuer = Issuer.create(domainSeparator, L);
        const client = Client.create(domainSeparator, L);

        const credentialContext = makeCredentialContext('spend-test-ctx');
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            crypto.getRandomValues(new Uint8Array(32)),
            ['origin.example.com'],
            credentialContext,
        );

        // Setup: issue credential
        const tokReq = await client.createTokenRequest(challenge, issuer.publicKeyBytes);
        const tokResBytes = issuer.issue(tokReq.encodedRequest, 100n, challenge);
        const tokRes = new ACTTokenResponse(tokResBytes);
        client.finalizeCredential(tokRes, issuer.publicKey);

        // Spend 30 credits (and return 0 of them - consume all 30)
        const spendToken = client.createSpendToken(challenge, 30n, issuer.keyId);
        expect(spendToken.tokenType).toBe(ACT.value);
        expect(client.getCredentialStatus(challenge)).toBe('spent');

        // Verify and get refund from issuer (return 0 of the 30 spent)
        // New balance = 100 - 30 + 0 = 70
        const { valid, refund } = issuer.verifyAndIssueRefund(spendToken.spendProof, 0n);
        expect(valid).toBe(true);
        if (refund === undefined) throw new Error('refund should be defined');

        // Process refund
        const newInfo = client.processRefund(challenge, refund, issuer.publicKey);
        expect(newInfo.balance).toBe(70n);
        expect(client.getCredentialStatus(challenge)).toBe('ready');
        expect(client.getBalance(challenge)).toBe(70n);
    });

    test('multiple spend cycles until exhausted', async () => {
        const issuer = Issuer.create(domainSeparator, L);
        const client = Client.create(domainSeparator, L);

        const credentialContext = makeCredentialContext('multi-spend-ctx');
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            crypto.getRandomValues(new Uint8Array(32)),
            ['origin.example.com'],
            credentialContext,
        );

        // Issue 50 credits
        const tokReq = await client.createTokenRequest(challenge, issuer.publicKeyBytes);
        const tokResBytes = issuer.issue(tokReq.encodedRequest, 50n, challenge);
        client.finalizeCredential(new ACTTokenResponse(tokResBytes), issuer.publicKey);

        // Spend 20, return 0 of them -> new balance = 50 - 20 = 30
        let token = client.createSpendToken(challenge, 20n, issuer.keyId);
        let result = issuer.verifyAndIssueRefund(token.spendProof, 0n);
        if (result.refund === undefined) throw new Error('refund should be defined');
        client.processRefund(challenge, result.refund, issuer.publicKey);
        expect(client.getBalance(challenge)).toBe(30n);

        // Spend 30, return 0 -> new balance = 30 - 30 = 0 (exhausted)
        token = client.createSpendToken(challenge, 30n, issuer.keyId);
        result = issuer.verifyAndIssueRefund(token.spendProof, 0n);
        if (result.refund === undefined) throw new Error('refund should be defined');
        client.processRefund(challenge, result.refund, issuer.publicKey);
        expect(client.getCredentialStatus(challenge)).toBe('exhausted');
    });
});

// =============================================================================
// Error Cases
// =============================================================================

describe('ACT Error Cases', () => {
    const domainSeparator = new TextEncoder().encode('ACT-v1:test:errors');
    const L = 8;

    test('NoCredentialError when spending without credential', () => {
        const client = Client.create(domainSeparator, L);
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            new Uint8Array(32),
            undefined,
            new Uint8Array(32),
        );

        expect(() => client.createSpendToken(challenge, 10n, new Uint8Array(32))).toThrow(
            NoCredentialError,
        );
    });

    test('InsufficientBalanceError when spending more than balance', async () => {
        const issuer = Issuer.create(domainSeparator, L);
        const client = Client.create(domainSeparator, L);

        const credentialContext = makeCredentialContext('insufficient-test');
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            new Uint8Array(32),
            undefined,
            credentialContext,
        );

        // Issue 50 credits
        const tokReq = await client.createTokenRequest(challenge, issuer.publicKeyBytes);
        const tokResBytes = issuer.issue(tokReq.encodedRequest, 50n, challenge);
        client.finalizeCredential(new ACTTokenResponse(tokResBytes), issuer.publicKey);

        // Try to spend 100
        expect(() => client.createSpendToken(challenge, 100n, issuer.keyId)).toThrow(
            InsufficientBalanceError,
        );

        try {
            client.createSpendToken(challenge, 100n, issuer.keyId);
        } catch (e) {
            expect(e).toBeInstanceOf(InsufficientBalanceError);
            const err = e as InstanceType<typeof InsufficientBalanceError>;
            expect(err.available).toBe(50n);
            expect(err.requested).toBe(100n);
        }
    });

    test('CredentialInUseError when spending twice without refund', async () => {
        const issuer = Issuer.create(domainSeparator, L);
        const client = Client.create(domainSeparator, L);

        const credentialContext = makeCredentialContext('double-spend-test');
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            new Uint8Array(32),
            undefined,
            credentialContext,
        );

        // Issue 100 credits
        const tokReq = await client.createTokenRequest(challenge, issuer.publicKeyBytes);
        const tokResBytes = issuer.issue(tokReq.encodedRequest, 100n, challenge);
        client.finalizeCredential(new ACTTokenResponse(tokResBytes), issuer.publicKey);

        // First spend
        client.createSpendToken(challenge, 10n, issuer.keyId);

        // Second spend without processing refund
        expect(() => client.createSpendToken(challenge, 10n, issuer.keyId)).toThrow(
            CredentialInUseError,
        );
    });

    test('finalize() throws with helpful message', async () => {
        const client = Client.create(domainSeparator, L);

        await expect(client.finalize(new ACTTokenResponse(new Uint8Array(10)))).rejects.toThrow(
            'Use finalizeCredential()',
        );
    });
});

// =============================================================================
// State Persistence
// =============================================================================

describe('ACT State Persistence', () => {
    const domainSeparator = new TextEncoder().encode('ACT-v1:test:persist');
    const L = 8;

    test('export and import preserves credentials', async () => {
        const issuer = Issuer.create(domainSeparator, L);
        const client1 = Client.create(domainSeparator, L);

        const credentialContext = makeCredentialContext('persist-test-ctx');
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            crypto.getRandomValues(new Uint8Array(32)),
            ['origin.example.com'],
            credentialContext,
        );

        // Issue credential to client1
        const tokReq = await client1.createTokenRequest(challenge, issuer.publicKeyBytes);
        const tokResBytes = issuer.issue(tokReq.encodedRequest, 100n, challenge);
        client1.finalizeCredential(new ACTTokenResponse(tokResBytes), issuer.publicKey);

        // Export and import to client2
        const exported = client1.export();
        expect(exported.version).toBe(1);
        expect(exported.L).toBe(L);
        expect(exported.credentials.length).toBe(1);

        const client2 = Client.import(exported);
        expect(client2.hasCredential(challenge)).toBe(true);
        expect(client2.getBalance(challenge)).toBe(100n);
    });

    test('toJSON and fromJSON work', async () => {
        const issuer = Issuer.create(domainSeparator, L);
        const client1 = Client.create(domainSeparator, L);

        const credentialContext = makeCredentialContext('json-persist-ctx');
        const challenge = new ACTTokenChallenge(
            'issuer.example.com',
            crypto.getRandomValues(new Uint8Array(32)),
            undefined,
            credentialContext,
        );

        // Issue credential
        const tokReq = await client1.createTokenRequest(challenge, issuer.publicKeyBytes);
        const tokResBytes = issuer.issue(tokReq.encodedRequest, 75n, challenge);
        client1.finalizeCredential(new ACTTokenResponse(tokResBytes), issuer.publicKey);

        // JSON roundtrip
        const json = client1.toJSON();
        const client2 = Client.fromJSON(json);

        expect(client2.getBalance(challenge)).toBe(75n);
    });
});
