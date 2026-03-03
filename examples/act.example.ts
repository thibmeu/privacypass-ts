// Copyright (c) 2026 Cloudflare, Inc.
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

import { TOKEN_TYPES, act } from '../src/index.js';
const { Client, Issuer, Origin, ACTTokenResponse } = act;

// Domain separator and L parameter must match between all parties
const DOMAIN_SEPARATOR = new TextEncoder().encode('example.com/act');
const L = 8; // Supports balances up to 2^L - 1 = 255

function setup() {
    // [ Issuer ] creates keys
    const issuer = Issuer.create(DOMAIN_SEPARATOR, L);
    const issuerPkBytes = issuer.publicKeyBytes;
    const issuerKeyId = issuer.keyId;

    // [ Origin ] creates state (knows issuer's public key)
    const origin = Origin.create(DOMAIN_SEPARATOR, L, issuerPkBytes, [
        'origin.example.com',
        'cdn.example.com',
    ]);

    // [ Client ] creates state
    const client = Client.create(DOMAIN_SEPARATOR, L);

    return { issuer, issuerPkBytes, issuerKeyId, origin, client };
}

interface ACTConfig {
    initialCredits: bigint;
    requestCost: bigint;
    returnCredits: bigint;
}

async function actVariant(config: ACTConfig): Promise<boolean> {
    const { initialCredits, requestCost, returnCredits } = config;

    // Protocol Setup
    const { issuer, issuerPkBytes, issuerKeyId, origin, client } = setup();

    // Online Protocol
    //                                       +--------------------------.
    // +--------+          +----------+      |  +--------+   +--------+  |
    // | Client |          | Attester |      |  | Issuer |   | Origin |  |
    // +---+----+          +-----+----+      |  +----+---+   +---+----+  |
    //     |                     |            `------|-----------|------'
    //     |                     |                   |           |
    //     |===================== Issuance ======================|
    //     +--------------------- Request ---------------------->|
    const credentialContext = crypto.getRandomValues(new Uint8Array(32));
    const challenge = origin.createChallenge(credentialContext);
    //     |<---------------- TokenChallenge --------------------+
    //     |                     |                   |           |
    if (!client.hasCredential(challenge)) {
        // |<=== Attestation ===>|                   |           |
        const tokenRequest = await client.createTokenRequest(challenge, issuerPkBytes);
        // +----------- CredentialRequest ---------->|           |
        const tokenResponseBytes = issuer.issue(
            tokenRequest.encodedRequest,
            initialCredits,
            challenge,
        ); // eslint-disable-line prettier/prettier
        // |<---------- CredentialResponse ----------+           |
        const tokenResponse = new ACTTokenResponse(tokenResponseBytes);
        // FinalizeCretendial    |                   |           |
        client.finalizeCredential(tokenResponse, origin.issuerPk);
        // |                     |                   |           |
    }
    //     |                     |                   |           |
    //     |================== Spend + Refund ===================|
    //     +----------- Request + Token ------------------------>|
    //     |                     |                   |           |
    const spendToken = client.createSpendToken(challenge, requestCost, issuerKeyId);
    //     |<---------- Response + TokenRefund ------------------+
    //     |                     |                   |           |
    const result = issuer.verifyAndIssueRefund(spendToken.spendProof, returnCredits);
    //     FinalizeRefund        |                   |           |
    //     |                     |                   |           |
    const refundInfo = client.processRefund(challenge, result.refund!, origin.issuerPk); // eslint-disable-line @typescript-eslint/no-non-null-assertion

    //                                       +--------------------------.
    // +--------+          +----------+      |  +--------+   +--------+  |
    // | Client |          | Attester |      |  | Issuer |   | Origin |  |
    // +---+----+          +-----+----+      |  +----+---+   +---+----+  |
    //     |                     |            `------|-----------|------'
    //     |                     |                   |           |
    //     |================== Multiple spends ==================|
    //     |                     |                   |           |
    let balance = refundInfo.balance;
    while (balance >= requestCost) {
        // +----------- Request + Token ------------------------>|
        // |                     |                   |           |
        const token = client.createSpendToken(challenge, requestCost, issuerKeyId);
        // |<---------- Response + TokenRefund ------------------+
        // |                     |                   |           |
        const verifyResult = issuer.verifyAndIssueRefund(token.spendProof, returnCredits);
        // FinalizeRefund        |                   |           |
        // |                     |                   |           |
        const info = client.processRefund(challenge, verifyResult.refund!, origin.issuerPk); // eslint-disable-line @typescript-eslint/no-non-null-assertion
        balance = info.balance;
    }

    // State persistence demo
    const exported = client.export();
    const restoredClient = Client.import(exported);
    if (restoredClient.getCredentialStatus(challenge) !== client.getCredentialStatus(challenge)) {
        return false;
    }

    console.log('Anonymous Credit tokens');
    console.log(`    Suite: ${TOKEN_TYPES.ACT.name}`);
    console.log(`    Valid token: true`);
    return true;
}

export function actCredentialFlow() {
    return actVariant({
        initialCredits: 100n,
        requestCost: 10n,
        returnCredits: 0n, // No partial refund in this example
    });
}
