// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Anonymous Credit Tokens (ACT) Example
//
// ACT enables privacy-preserving credit systems where clients can:
// - Receive credits from an issuer without linkability
// - Spend partial amounts while keeping remaining balance private
// - Get refunds that cannot be linked to the original spend
//
// Unlike standard Privacy Pass tokens (single-use), ACT credentials
// persist across multiple spend operations until exhausted.
//
// Specification: draft-schlesinger-privacypass-act-01
//               draft-schlesinger-cfrg-act-01
//               draft-meunier-privacypass-reverse-flow-03

import { act } from '../src/index.js';
const { Client, Issuer, Origin, ACTTokenResponse } = act;

// Domain separator and L parameter must match between all parties
const DOMAIN_SEPARATOR = new TextEncoder().encode('example.com/act');
const L = 8; // Supports balances up to 2^L - 1 = 255

export async function actCredentialFlow(): Promise<boolean> {
    console.log('Anonymous Credit Tokens (ACT)');
    console.log('');
    console.log('Token type: 0xE5AD (ACT Ristretto255)');
    console.log(`Balance bits (L): ${L} (max balance: ${(1n << BigInt(L)) - 1n})`);
    console.log('');

    // =========================================================================
    // Protocol Setup
    // =========================================================================

    // [ Issuer ] creates keys
    const issuer = Issuer.create(DOMAIN_SEPARATOR, L);
    const issuerPkBytes = issuer.publicKeyBytes;
    const issuerKeyId = issuer.keyId;

    console.log('Issuer key ID:', toHex(issuerKeyId).slice(0, 16) + '...');

    // [ Origin ] creates state (knows issuer's public key)
    const origin = Origin.create(DOMAIN_SEPARATOR, L, issuerPkBytes, [
        'origin.example.com',
        'cdn.example.com',
    ]);

    // [ Client ] creates state
    const client = Client.create(DOMAIN_SEPARATOR, L);

    // =========================================================================
    // Phase 1: Initial request triggers issuance
    // =========================================================================
    console.log('');
    console.log('--- Phase 1: Issuance ---');

    // Client -> Origin: Initial request (no token yet)
    // Origin -> Client: TokenChallenge
    const credentialContext = crypto.getRandomValues(new Uint8Array(32));
    const challenge = origin.createChallenge(credentialContext);

    console.log(
        'Origin sends challenge for credential context:',
        toHex(credentialContext).slice(0, 16) + '...',
    );

    // Client checks if they have a credential for this context
    const hasCredential = client.hasCredential(challenge);
    console.log(`Client has credential: ${hasCredential}`);

    if (!hasCredential) {
        // Client needs to get a credential from the issuer
        // Client -> Issuer: TokenRequest
        const tokenRequest = await client.createTokenRequest(challenge, issuerPkBytes);
        const tokenRequestBytes = tokenRequest.serialize();

        console.log(`Client sends TokenRequest (${tokenRequestBytes.length} bytes)`);

        // Issuer processes request and issues credits
        // In a real deployment, this would happen over HTTP
        const INITIAL_CREDITS = 100n;
        const tokenResponseBytes = issuer.issue(
            tokenRequest.encodedRequest,
            INITIAL_CREDITS,
            challenge,
        );

        console.log(`Issuer issues ${INITIAL_CREDITS} credits`);

        // Issuer -> Client: TokenResponse
        const tokenResponse = new ACTTokenResponse(tokenResponseBytes);

        // Client finalizes credential
        const info = client.finalizeCredential(tokenResponse, origin.issuerPk);
        console.log(`Client credential ready, balance: ${info.balance}`);
    }

    // =========================================================================
    // Phase 2: Spend + Refund (simulated request cycle)
    // =========================================================================
    console.log('');
    console.log('--- Phase 2: Spend + Refund ---');

    const COST = 10n;
    console.log(`Request cost: ${COST} credits`);

    // Client creates spend token
    const spendToken = client.createSpendToken(challenge, COST, issuerKeyId);
    console.log(`Client creates spend token (${spendToken.serialize().length} bytes)`);

    // Client -> Origin: Request with Authorization header containing ACTToken
    // Origin decodes and validates token structure
    const decoded = origin.decodeToken(spendToken);
    if (!decoded.valid || !decoded.spendProof) {
        console.log('ERROR: Invalid token structure');
        return false;
    }
    console.log('Origin validates token structure');

    // Origin -> Issuer: Forward spend proof for verification + refund
    // (In real deployment, this is via internal API)
    const RETURN_CREDITS = 0n; // No partial refund in this example
    const result = issuer.verifyAndIssueRefund(spendToken.spendProof, RETURN_CREDITS);
    if (!result.valid || !result.refund) {
        console.log('ERROR: Spend proof verification failed');
        return false;
    }
    console.log('Issuer verifies spend proof');

    // Issuer -> Origin -> Client: Refund (via PrivacyPass-Reverse header)
    const refundInfo = client.processRefund(challenge, result.refund, origin.issuerPk);
    console.log(`Client processes refund, new balance: ${refundInfo.balance}`);

    // =========================================================================
    // Phase 3: Multiple spends until exhausted
    // =========================================================================
    console.log('');
    console.log('--- Phase 3: Multiple Spends ---');

    let balance = refundInfo.balance;
    let spendCount = 1; // Already did one spend

    while (balance >= COST) {
        // Each spend cycle
        const token = client.createSpendToken(challenge, COST, issuerKeyId);
        const verifyResult = issuer.verifyAndIssueRefund(token.spendProof, RETURN_CREDITS);
        if (!verifyResult.valid || !verifyResult.refund) {
            console.log('ERROR: Spend failed');
            return false;
        }
        const info = client.processRefund(challenge, verifyResult.refund, origin.issuerPk);
        balance = info.balance;
        spendCount++;
        console.log(`  Spend #${spendCount}: balance now ${balance}`);
    }

    console.log('');
    console.log(`Total spends: ${spendCount}`);
    console.log(`Final balance: ${balance}`);
    console.log(`Credential status: ${client.getCredentialStatus(challenge)}`);

    // =========================================================================
    // State persistence demo
    // =========================================================================
    console.log('');
    console.log('--- State Persistence ---');

    // Export client state
    const exported = client.export();
    console.log(`Exported state: ${JSON.stringify(exported).length} bytes`);

    // Import into new client instance
    const restoredClient = Client.import(exported);
    console.log(
        `Restored client, credential status: ${restoredClient.getCredentialStatus(challenge)}`,
    );

    const success =
        restoredClient.getCredentialStatus(challenge) === client.getCredentialStatus(challenge);
    console.log('');
    console.log(`Success: ${success}`);

    return success;
}

// Utility
function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}
