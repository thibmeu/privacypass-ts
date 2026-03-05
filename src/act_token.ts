// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Anonymous Credit Tokens (ACT) for Privacy Pass
//
// Specification: draft-schlesinger-privacypass-act-01
//               draft-schlesinger-cfrg-act-01
//               draft-meunier-privacypass-reverse-flow-03
//
// ACT enables privacy-preserving credit systems where:
// - Clients receive credentials with a credit balance
// - Spend operations deduct from the balance with unlinkability
// - Refunds restore remaining balance after each spend

import {
    ristretto255,
    generateParameters,
    keyGen,
    issueRequest,
    issueResponse,
    verifyIssuance,
    proveSpend,
    verifySpendProof,
    issueRefund,
    constructRefundToken,
    encodeIssuanceRequest,
    decodeIssuanceRequest,
    encodeIssuanceResponse,
    decodeIssuanceResponse,
    encodeSpendProof,
    decodeSpendProof,
    encodeRefund,
    decodeRefund,
    encodeCreditToken,
    decodeCreditToken,
    encodeIssuanceState,
    decodeIssuanceState,
    encodeSpendState,
    decodeSpendState,
    encodePublicKey,
    decodePublicKey,
    encodePrivateKey,
    decodePrivateKey,
    WebCryptoPRNG,
    type SystemParams,
    type PublicKey,
    type PrivateKey,
    type CreditToken,
    type IssuanceState,
    type SpendState,
    type SpendProof,
    type PRNG,
} from 'act-ts';

import { sha256 } from '@noble/hashes/sha2';
import { equalBytes } from '@noble/curves/utils.js';
import { joinAll } from './util.js';
import { TokenChallenge, type TokenTypeEntry } from './auth_scheme/private_token.js';
import type { PrivacyPassClient } from './issuance.js';

// =============================================================================
// Token Type Entry
// =============================================================================

// Token Type ACT (Ristretto255)
// Value: 0xE5AD (mnemonic: "ACT" in a stylized form)
// Note: TokenTypeValue union doesn't include 0xe5ad, so we use a broader type
export const ACT_TOKEN_TYPE = 0xe5ad;
export const ACT: Readonly<Omit<TokenTypeEntry, 'value'> & { value: number }> = {
    value: ACT_TOKEN_TYPE,
    name: 'ACT (Ristretto255)',
    Nk: 0, // Not applicable - ACT uses sigma proofs, not fixed-size blinded messages
    Nid: 32, // SHA-256 hash of issuer public key
    publicVerifiable: false,
    publicMetadata: false,
    privateMetadata: false,
} as const;

// =============================================================================
// Error Classes
// =============================================================================

export class DeserializationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'DeserializationError';
    }
}

export class ACTError extends Error {
    constructor(
        message: string,
        public readonly code: string,
    ) {
        super(message);
        this.name = 'ACTError';
    }
}

export class NoCredentialError extends ACTError {
    constructor(message = 'no credential available for this context') {
        super(message, 'NO_CREDENTIAL');
        this.name = 'NoCredentialError';
    }
}

export class InsufficientBalanceError extends ACTError {
    constructor() {
        super('insufficient balance', 'INSUFFICIENT_BALANCE');
        this.name = 'InsufficientBalanceError';
    }
}

export class CredentialInUseError extends ACTError {
    constructor(message = 'credential has a pending spend operation') {
        super(message, 'CREDENTIAL_IN_USE');
        this.name = 'CredentialInUseError';
    }
}

export class InvalidRefundError extends ACTError {
    constructor(message = 'refund verification failed') {
        super(message, 'INVALID_REFUND');
        this.name = 'InvalidRefundError';
    }
}

// =============================================================================
// ACT Token Challenge (extends base TokenChallenge with credentialContext)
// =============================================================================

export class ACTTokenChallenge extends TokenChallenge {
    // Extended TokenChallenge per draft-schlesinger-privacypass-act-01 Section 7
    //
    // struct {
    //     uint16_t token_type;
    //     opaque issuer_name<1..2^16-1>;
    //     opaque redemption_context<0..32>;
    //     opaque origin_info<0..2^16-1>;
    //     opaque credential_context<0..32>;  // ACT extension
    // } ACTTokenChallenge;

    static readonly CREDENTIAL_CONTEXT_LENGTH = [0, 32];

    constructor(
        issuerName: string,
        redemptionContext: Uint8Array,
        originInfo: string[] | undefined,
        public readonly credentialContext: Uint8Array,
    ) {
        super(ACT.value, issuerName, redemptionContext, originInfo);

        if (!ACTTokenChallenge.CREDENTIAL_CONTEXT_LENGTH.includes(credentialContext.length)) {
            throw new Error('invalid credentialContext size: must be 0 or 32 bytes');
        }
    }

    static override deserialize(bytes: Uint8Array): ACTTokenChallenge {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        let offset = 0;

        const type = view.getUint16(offset);
        offset += 2;
        if (type !== ACT.value) {
            throw new DeserializationError(`invalid token type: expected ${ACT.value}, got ${type}`);
        }

        // issuer_name
        let len = view.getUint16(offset);
        offset += 2;
        ensureLength(bytes, offset, len);
        const issuerName = new TextDecoder().decode(bytes.subarray(offset, offset + len));
        offset += len;

        // redemption_context
        len = view.getUint8(offset);
        offset += 1;
        ensureLength(bytes, offset, len);
        const redemptionContext = bytes.subarray(offset, offset + len);
        offset += len;

        // origin_info
        len = view.getUint16(offset);
        offset += 2;
        ensureLength(bytes, offset, len);
        let originInfo: string[] | undefined;
        if (len > 0) {
            originInfo = new TextDecoder().decode(bytes.subarray(offset, offset + len)).split(',');
        }
        offset += len;

        // credential_context (ACT extension)
        len = view.getUint8(offset);
        offset += 1;
        ensureLength(bytes, offset, len);
        const credentialContext = bytes.subarray(offset, offset + len);

        return new ACTTokenChallenge(issuerName, redemptionContext, originInfo, credentialContext);
    }

    override serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();
        const te = new TextEncoder();

        // token_type
        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        // issuer_name
        const issuerNameBytes = te.encode(this.issuerName);
        b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, issuerNameBytes.length);
        output.push(b);
        output.push(issuerNameBytes.buffer.slice(0, issuerNameBytes.length));

        // redemption_context
        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.redemptionContext.length);
        output.push(b);
        b = (this.redemptionContext.buffer as ArrayBuffer).slice(
            this.redemptionContext.byteOffset,
            this.redemptionContext.byteOffset + this.redemptionContext.byteLength,
        );
        output.push(b);

        // origin_info
        let originInfoBytes = new Uint8Array(0);
        if (this.originInfo) {
            originInfoBytes = te.encode(this.originInfo.join(','));
        }
        b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, originInfoBytes.length);
        output.push(b);
        output.push(originInfoBytes.buffer.slice(0, originInfoBytes.length));

        // credential_context (ACT extension)
        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.credentialContext.length);
        output.push(b);
        b = (this.credentialContext.buffer as ArrayBuffer).slice(
            this.credentialContext.byteOffset,
            this.credentialContext.byteOffset + this.credentialContext.byteLength,
        );
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}

// =============================================================================
// Wire Format Types
// =============================================================================

export class ACTTokenRequest {
    // struct {
    //     uint16_t token_type = 0xE5AD;
    //     uint8_t truncated_token_key_id;
    //     opaque encoded_request<1..2^16-1>;
    // } ACTTokenRequest;

    public readonly tokenType = ACT.value;

    constructor(
        public readonly truncatedTokenKeyId: number,
        public readonly encodedRequest: Uint8Array,
    ) {
        if (truncatedTokenKeyId < 0 || truncatedTokenKeyId > 255) {
            throw new Error('truncatedTokenKeyId must be a single byte');
        }
    }

    static deserialize(bytes: Uint8Array): ACTTokenRequest {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        let offset = 0;

        const type = view.getUint16(offset);
        offset += 2;
        if (type !== ACT.value) {
            throw new DeserializationError(`invalid token type: expected ${ACT.value}, got ${type}`);
        }

        const truncatedTokenKeyId = view.getUint8(offset);
        offset += 1;

        const len = view.getUint16(offset);
        offset += 2;
        ensureLength(bytes, offset, len);
        const encodedRequest = bytes.subarray(offset, offset + len);

        return new ACTTokenRequest(truncatedTokenKeyId, encodedRequest);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        // token_type
        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        // truncated_token_key_id
        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.truncatedTokenKeyId);
        output.push(b);

        // encoded_request length + data
        b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.encodedRequest.length);
        output.push(b);
        b = (this.encodedRequest.buffer as ArrayBuffer).slice(
            this.encodedRequest.byteOffset,
            this.encodedRequest.byteOffset + this.encodedRequest.byteLength,
        );
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}

export class ACTTokenResponse {
    // struct {
    //     opaque encoded_response<1..2^16-1>;
    // } ACTTokenResponse;

    constructor(public readonly encodedResponse: Uint8Array) {}

    static deserialize(bytes: Uint8Array): ACTTokenResponse {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        let offset = 0;

        const len = view.getUint16(offset);
        offset += 2;
        ensureLength(bytes, offset, len);
        const encodedResponse = bytes.subarray(offset, offset + len);

        return new ACTTokenResponse(encodedResponse);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        // encoded_response length + data
        const b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.encodedResponse.length);
        output.push(b);
        const data = (this.encodedResponse.buffer as ArrayBuffer).slice(
            this.encodedResponse.byteOffset,
            this.encodedResponse.byteOffset + this.encodedResponse.byteLength,
        );
        output.push(data);

        return new Uint8Array(joinAll(output));
    }
}

export class ACTToken {
    // struct {
    //     uint16_t token_type = 0xE5AD;
    //     uint8_t challenge_digest[32];
    //     uint8_t issuer_key_id[32];
    //     opaque spend_proof<1..2^16-1>;
    // } ACTToken;

    static readonly CHALLENGE_DIGEST_LENGTH = 32;
    static readonly ISSUER_KEY_ID_LENGTH = 32;

    public readonly tokenType = ACT.value;

    constructor(
        public readonly challengeDigest: Uint8Array,
        public readonly issuerKeyId: Uint8Array,
        public readonly spendProof: Uint8Array,
    ) {
        if (challengeDigest.length !== ACTToken.CHALLENGE_DIGEST_LENGTH) {
            throw new Error(`challengeDigest must be ${ACTToken.CHALLENGE_DIGEST_LENGTH} bytes`);
        }
        if (issuerKeyId.length !== ACTToken.ISSUER_KEY_ID_LENGTH) {
            throw new Error(`issuerKeyId must be ${ACTToken.ISSUER_KEY_ID_LENGTH} bytes`);
        }
    }

    static deserialize(bytes: Uint8Array): ACTToken {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        let offset = 0;

        const type = view.getUint16(offset);
        offset += 2;
        if (type !== ACT.value) {
            throw new DeserializationError(`invalid token type: expected ${ACT.value}, got ${type}`);
        }

        ensureLength(bytes, offset, ACTToken.CHALLENGE_DIGEST_LENGTH);
        const challengeDigest = bytes.subarray(offset, offset + ACTToken.CHALLENGE_DIGEST_LENGTH);
        offset += ACTToken.CHALLENGE_DIGEST_LENGTH;

        ensureLength(bytes, offset, ACTToken.ISSUER_KEY_ID_LENGTH);
        const issuerKeyId = bytes.subarray(offset, offset + ACTToken.ISSUER_KEY_ID_LENGTH);
        offset += ACTToken.ISSUER_KEY_ID_LENGTH;

        const len = view.getUint16(offset);
        offset += 2;
        ensureLength(bytes, offset, len);
        const spendProof = bytes.subarray(offset, offset + len);

        return new ACTToken(challengeDigest, issuerKeyId, spendProof);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        // token_type
        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        // challenge_digest - use slice to handle Uint8Array views correctly
        b = (this.challengeDigest.buffer as ArrayBuffer).slice(
            this.challengeDigest.byteOffset,
            this.challengeDigest.byteOffset + this.challengeDigest.byteLength,
        );
        output.push(b);

        // issuer_key_id - use slice to handle Uint8Array views correctly
        b = (this.issuerKeyId.buffer as ArrayBuffer).slice(
            this.issuerKeyId.byteOffset,
            this.issuerKeyId.byteOffset + this.issuerKeyId.byteLength,
        );
        output.push(b);

        // spend_proof length + data
        b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.spendProof.length);
        output.push(b);
        b = (this.spendProof.buffer as ArrayBuffer).slice(
            this.spendProof.byteOffset,
            this.spendProof.byteOffset + this.spendProof.byteLength,
        );
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}

// =============================================================================
// Credential State Types
// =============================================================================

export interface CredentialInfo {
    balance: bigint;
    context: Uint8Array;
}

type CredentialState =
    | { status: 'ready'; credential: CreditToken; ctx: Uint8Array }
    | { status: 'spent'; spendState: SpendState; proof: SpendProof; ctx: Uint8Array }
    | { status: 'exhausted' };

interface PendingIssuance {
    state: IssuanceState;
    key: string;
    challenge: ACTTokenChallenge;
    issuerKeyId: Uint8Array;
}

// =============================================================================
// Client State Persistence
// =============================================================================

interface SerializedCredentialState {
    status: 'ready' | 'spent' | 'exhausted';
    credential?: string; // base64
    spendState?: string; // base64
    proof?: string; // base64
    ctx?: string; // base64
}

// SECURITY: ACTClientState contains secret key material (k, r scalars) in plaintext.
// Store encrypted at rest and transmit only over secure channels.
export interface ACTClientState {
    version: number;
    L: number;
    domainSeparator: string; // base64
    credentials: Array<{ key: string; state: SerializedCredentialState }>;
    pendingIssuance?: {
        state: string; // base64
        key: string;
        challenge: string; // base64
        issuerKeyId: string; // base64
    };
}

// =============================================================================
// ACT Client
// =============================================================================

/**
 * ACT Client for Privacy Pass.
 *
 * Note: ACT implements PrivacyPassClient interface for createTokenRequest() and
 * deserializeTokenResponse(), but finalize() throws because ACT credentials are
 * stateful and persist across spends. Use finalizeCredential() instead.
 *
 * For generic Privacy Pass flows, use the ACT-specific methods:
 * - finalizeCredential() instead of finalize()
 * - createSpendToken() for subsequent requests
 * - processRefund() to update balance after spend
 */
export class Client implements PrivacyPassClient {
    private readonly credentials = new Map<string, CredentialState>();
    private pendingIssuance?: PendingIssuance;
    private readonly rng: PRNG;

    constructor(
        private readonly params: SystemParams,
        rng?: PRNG,
    ) {
        this.rng = rng ?? new WebCryptoPRNG();
    }

    // -------------------------------------------------------------------------
    // Factory methods
    // -------------------------------------------------------------------------

    static create(domainSeparator: Uint8Array, L: number, rng?: PRNG): Client {
        const params = generateParameters(ristretto255, domainSeparator, L);
        return new Client(params, rng);
    }

    // -------------------------------------------------------------------------
    // PrivacyPassClient interface
    // -------------------------------------------------------------------------

    createTokenRequest(
        tokChl: TokenChallenge,
        issuerPublicKey: Uint8Array,
    ): Promise<ACTTokenRequest> {
        if (!(tokChl instanceof ACTTokenChallenge)) {
            return Promise.reject(new ACTError('expected ACTTokenChallenge', 'INVALID_CHALLENGE'));
        }

        const key = this.deriveKey(tokChl);

        // Compute issuer key ID
        const issuerKeyId = sha256(issuerPublicKey);

        // Compute request_context per §8.2:
        // request_context = concat(issuer_name, origin_info, credential_context, issuer_key_id)
        const requestContext = deriveRequestContext(
            tokChl.issuerName,
            tokChl.originInfo,
            tokChl.credentialContext,
            issuerKeyId,
        );
        const ctx = this.params.group.hashToScalar(requestContext);

        const [request, state] = issueRequest(this.params, ctx, this.rng);

        this.pendingIssuance = {
            state,
            key,
            challenge: tokChl,
            issuerKeyId,
        };

        const encodedRequest = encodeIssuanceRequest(request);
        const truncatedTokenKeyId = issuerKeyId[issuerKeyId.length - 1] ?? 0;

        return Promise.resolve(new ACTTokenRequest(truncatedTokenKeyId, encodedRequest));
    }

    deserializeTokenResponse(bytes: Uint8Array): ACTTokenResponse {
        return ACTTokenResponse.deserialize(bytes);
    }

    finalize(_tokRes: ACTTokenResponse): Promise<never> {
        // ACT credentials are stateful and persist across spends.
        // Use finalizeCredential() instead.
        return Promise.reject(
            new ACTError(
                'ACT tokens are stateful. Use finalizeCredential() instead of finalize().',
                'USE_FINALIZE_CREDENTIAL',
            ),
        );
    }

    // -------------------------------------------------------------------------
    // ACT-specific methods
    // -------------------------------------------------------------------------

    finalizeCredential(tokRes: ACTTokenResponse, issuerPk: PublicKey): CredentialInfo {
        if (!this.pendingIssuance) {
            throw new ACTError('no pending issuance', 'NO_PENDING_ISSUANCE');
        }

        const { state, key, challenge } = this.pendingIssuance;
        this.pendingIssuance = undefined;

        const response = decodeIssuanceResponse(this.params.group, tokRes.encodedResponse);
        const credential = verifyIssuance(this.params, issuerPk, response, state);

        this.credentials.set(key, {
            status: 'ready',
            credential,
            ctx: challenge.credentialContext,
        });

        return {
            balance: credential.c,
            context: challenge.credentialContext,
        };
    }

    createSpendToken(tokChl: ACTTokenChallenge, cost: bigint, issuerKeyId: Uint8Array): ACTToken {
        const key = this.deriveKey(tokChl);
        const state = this.credentials.get(key);

        if (!state) {
            throw new NoCredentialError();
        }

        if (state.status === 'exhausted') {
            throw new NoCredentialError('credential is exhausted');
        }

        if (state.status === 'spent') {
            throw new CredentialInUseError();
        }

        const { credential, ctx } = state;

        if (credential.c < cost) {
            throw new InsufficientBalanceError();
        }

        const [proof, spendState] = proveSpend(this.params, credential, cost, this.rng);

        // Transition to spent state
        this.credentials.set(key, {
            status: 'spent',
            spendState,
            proof,
            ctx,
        });

        // Compute challenge digest
        const challengeDigest = sha256(tokChl.serialize());

        // Encode spend proof
        const spendProofBytes = encodeSpendProof(this.params.group, proof);

        return new ACTToken(challengeDigest, issuerKeyId, spendProofBytes);
    }

    processRefund(
        tokChl: ACTTokenChallenge,
        refundBytes: Uint8Array,
        issuerPk: PublicKey,
    ): CredentialInfo {
        const key = this.deriveKey(tokChl);
        const state = this.credentials.get(key);

        if (!state || state.status !== 'spent') {
            throw new ACTError('no pending spend for this context', 'NO_PENDING_SPEND');
        }

        const { spendState, proof, ctx } = state;

        const refund = decodeRefund(this.params.group, refundBytes);
        const newCredential = constructRefundToken(
            this.params,
            issuerPk,
            proof,
            refund,
            spendState,
        );

        if (newCredential.c === 0n) {
            this.credentials.set(key, { status: 'exhausted' });
        } else {
            this.credentials.set(key, {
                status: 'ready',
                credential: newCredential,
                ctx,
            });
        }

        return {
            balance: newCredential.c,
            context: ctx,
        };
    }

    // -------------------------------------------------------------------------
    // Inspection methods
    // -------------------------------------------------------------------------

    hasCredential(tokChl: ACTTokenChallenge): boolean {
        const key = this.deriveKey(tokChl);
        const state = this.credentials.get(key);
        return state?.status === 'ready';
    }

    getBalance(tokChl: ACTTokenChallenge): bigint | undefined {
        const key = this.deriveKey(tokChl);
        const state = this.credentials.get(key);
        if (state?.status === 'ready') {
            return state.credential.c;
        }
        return undefined;
    }

    getCredentialStatus(tokChl: ACTTokenChallenge): 'ready' | 'spent' | 'exhausted' | 'none' {
        const key = this.deriveKey(tokChl);
        const state = this.credentials.get(key);
        return state?.status ?? 'none';
    }

    // -------------------------------------------------------------------------
    // State persistence
    //
    // SECURITY: Exported state contains secret scalars (k, r) in plaintext.
    // Applications must encrypt before storage and use secure channels.
    // -------------------------------------------------------------------------

    export(): ACTClientState {
        const credentials: Array<{ key: string; state: SerializedCredentialState }> = [];

        for (const [key, state] of this.credentials) {
            const serialized: SerializedCredentialState = { status: state.status };

            if (state.status === 'ready') {
                serialized.credential = toBase64(
                    encodeCreditToken(this.params.group, state.credential),
                );
                serialized.ctx = toBase64(state.ctx);
            } else if (state.status === 'spent') {
                serialized.spendState = toBase64(
                    encodeSpendState(this.params.group, state.spendState),
                );
                serialized.proof = toBase64(encodeSpendProof(this.params.group, state.proof));
                serialized.ctx = toBase64(state.ctx);
            }

            credentials.push({ key, state: serialized });
        }

        const result: ACTClientState = {
            version: 1,
            L: this.params.L,
            domainSeparator: toBase64(this.params.domainSeparator),
            credentials,
        };

        if (this.pendingIssuance) {
            result.pendingIssuance = {
                state: toBase64(encodeIssuanceState(this.pendingIssuance.state)),
                key: this.pendingIssuance.key,
                challenge: toBase64(this.pendingIssuance.challenge.serialize()),
                issuerKeyId: toBase64(this.pendingIssuance.issuerKeyId),
            };
        }

        return result;
    }

    static import(exported: ACTClientState, rng?: PRNG): Client {
        if (exported.version !== 1) {
            throw new ACTError(
                `unsupported state version: ${exported.version}`,
                'INVALID_STATE_VERSION',
            );
        }

        const domainSeparator = fromBase64(exported.domainSeparator);
        const params = generateParameters(ristretto255, domainSeparator, exported.L);
        const client = new Client(params, rng);

        for (const { key, state } of exported.credentials) {
            if (state.status === 'ready' && state.credential && state.ctx) {
                const credential = decodeCreditToken(params.group, fromBase64(state.credential));
                client.credentials.set(key, {
                    status: 'ready',
                    credential,
                    ctx: fromBase64(state.ctx),
                });
            } else if (state.status === 'spent' && state.spendState && state.proof && state.ctx) {
                const spendState = decodeSpendState(params.group, fromBase64(state.spendState));
                const proof = decodeSpendProof(params.group, params.L, fromBase64(state.proof));
                client.credentials.set(key, {
                    status: 'spent',
                    spendState,
                    proof,
                    ctx: fromBase64(state.ctx),
                });
            } else if (state.status === 'exhausted') {
                client.credentials.set(key, { status: 'exhausted' });
            }
        }

        if (exported.pendingIssuance) {
            const issuanceState = decodeIssuanceState(
                params.group,
                fromBase64(exported.pendingIssuance.state),
            );
            const challenge = ACTTokenChallenge.deserialize(
                fromBase64(exported.pendingIssuance.challenge),
            );
            client.pendingIssuance = {
                state: issuanceState,
                key: exported.pendingIssuance.key,
                challenge,
                issuerKeyId: fromBase64(exported.pendingIssuance.issuerKeyId),
            };
        }

        return client;
    }

    toJSON(): string {
        return JSON.stringify(this.export());
    }

    static fromJSON(json: string, rng?: PRNG): Client {
        const exported = JSON.parse(json) as ACTClientState;
        return Client.import(exported, rng);
    }

    // -------------------------------------------------------------------------
    // Internal methods
    // -------------------------------------------------------------------------

    private deriveKey(tokChl: ACTTokenChallenge): string {
        // Key = SHA-256(issuer_name || origin_info || credential_context)
        const te = new TextEncoder();
        const parts: Uint8Array[] = [
            te.encode(tokChl.issuerName),
            te.encode(tokChl.originInfo?.join(',') ?? ''),
            tokChl.credentialContext,
        ];

        const combined = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
        let offset = 0;
        for (const part of parts) {
            combined.set(part, offset);
            offset += part.length;
        }

        return toHex(sha256(combined));
    }
}

// =============================================================================
// Issuer (for testing and local deployments)
// =============================================================================

export class Issuer {
    constructor(
        private readonly params: SystemParams,
        private readonly privateKey: PrivateKey,
        public readonly publicKey: PublicKey,
        private readonly rng: PRNG = new WebCryptoPRNG(),
    ) {}

    static create(domainSeparator: Uint8Array, L: number, rng?: PRNG): Issuer {
        const actualRng = rng ?? new WebCryptoPRNG();
        const params = generateParameters(ristretto255, domainSeparator, L);
        const { privateKey, publicKey } = keyGen(ristretto255, actualRng);
        return new Issuer(params, privateKey, publicKey, actualRng);
    }

    get publicKeyBytes(): Uint8Array {
        return encodePublicKey(this.publicKey);
    }

    get keyId(): Uint8Array {
        return sha256(this.publicKeyBytes);
    }

    issue(requestBytes: Uint8Array, credits: bigint, challenge: ACTTokenChallenge): Uint8Array {
        const request = decodeIssuanceRequest(this.params.group, requestBytes);

        // Compute request_context per §8.2:
        // request_context = concat(issuer_name, origin_info, credential_context, issuer_key_id)
        const requestContext = deriveRequestContext(
            challenge.issuerName,
            challenge.originInfo,
            challenge.credentialContext,
            this.keyId,
        );
        const ctx = this.params.group.hashToScalar(requestContext);

        const response = issueResponse(
            this.params,
            this.privateKey,
            request,
            credits,
            ctx,
            this.rng,
        );
        // encodeIssuanceResponse expects response with ctx for wire format
        return encodeIssuanceResponse(this.params.group, { ...response, ctx });
    }

    verifyAndIssueRefund(
        proofBytes: Uint8Array,
        returnCredits: bigint,
    ): { valid: boolean; refund?: Uint8Array } {
        const proof = decodeSpendProof(this.params.group, this.params.L, proofBytes);

        // verifySpendProof throws on invalid proof
        try {
            verifySpendProof(this.params, this.privateKey, proof);
        } catch {
            return { valid: false };
        }

        const refund = issueRefund(this.params, this.privateKey, proof, returnCredits, this.rng);
        return {
            valid: true,
            refund: encodeRefund(this.params.group, refund),
        };
    }
}

// =============================================================================
// Origin (for testing and local deployments)
// =============================================================================

export class Origin {
    constructor(
        private readonly params: SystemParams,
        public readonly issuerPk: PublicKey, // Exposed for forwarding to issuer
        public readonly issuerKeyId: Uint8Array,
        public readonly originInfo: string[],
        public readonly issuerName: string,
    ) {}

    static create(
        domainSeparator: Uint8Array,
        L: number,
        issuerPkBytes: Uint8Array,
        originInfo: string[],
        issuerName: string,
    ): Origin {
        const params = generateParameters(ristretto255, domainSeparator, L);
        const issuerPk = decodePublicKey(params.group, issuerPkBytes);
        const issuerKeyId = sha256(issuerPkBytes);
        return new Origin(params, issuerPk, issuerKeyId, originInfo, issuerName);
    }

    createChallenge(
        credentialContext: Uint8Array,
        redemptionContext?: Uint8Array,
    ): ACTTokenChallenge {
        const ctx = redemptionContext ?? crypto.getRandomValues(new Uint8Array(32));
        return new ACTTokenChallenge(this.issuerName, ctx, this.originInfo, credentialContext);
    }

    /**
     * Decode a token and verify its structure (issuer key ID match).
     * Note: Full spend proof verification requires the issuer's private key.
     * In a real deployment, the Origin forwards the proof to the Issuer for verification.
     */
    decodeToken(token: ACTToken): { valid: boolean; spendProof?: SpendProof } {
        // Verify issuer key ID matches
        if (!equalBytes(token.issuerKeyId, this.issuerKeyId)) {
            return { valid: false };
        }

        // Decode spend proof (verification requires issuer's private key)
        try {
            const proof = decodeSpendProof(this.params.group, this.params.L, token.spendProof);
            return { valid: true, spendProof: proof };
        } catch {
            return { valid: false };
        }
    }
}

// =============================================================================
// Utility functions
// =============================================================================

// Derives request_context per draft-schlesinger-privacypass-act-01 §8.2:
// context_input = concat(issuer_name, origin_info, credential_context, issuer_key_id)
// request_context = HashToScalar(context_input)
//
// Per §3, concat() uses length-prefixed concatenation with 2-byte big-endian lengths.
function deriveRequestContext(
    issuerName: string,
    originInfo: string[] | undefined,
    credentialContext: Uint8Array,
    issuerKeyId: Uint8Array,
): Uint8Array {
    const te = new TextEncoder();

    // Each part is prefixed with 2-byte big-endian length per spec §3
    const issuerBytes = te.encode(issuerName);
    const originBytes = te.encode(originInfo?.join(',') ?? '');

    // Calculate total length: 4 parts × 2-byte prefix + data
    const totalLength =
        2 + issuerBytes.length + 2 + originBytes.length + 2 + credentialContext.length + 2 + issuerKeyId.length;

    const result = new Uint8Array(totalLength);
    const view = new DataView(result.buffer);
    let offset = 0;

    // issuer_name with 2-byte length prefix
    view.setUint16(offset, issuerBytes.length, false); // big-endian
    offset += 2;
    result.set(issuerBytes, offset);
    offset += issuerBytes.length;

    // origin_info with 2-byte length prefix
    view.setUint16(offset, originBytes.length, false);
    offset += 2;
    result.set(originBytes, offset);
    offset += originBytes.length;

    // credential_context with 2-byte length prefix
    view.setUint16(offset, credentialContext.length, false);
    offset += 2;
    result.set(credentialContext, offset);
    offset += credentialContext.length;

    // issuer_key_id with 2-byte length prefix
    view.setUint16(offset, issuerKeyId.length, false);
    offset += 2;
    result.set(issuerKeyId, offset);

    return result;
}

function ensureLength(bytes: Uint8Array, offset: number, len: number): void {
    if (offset + len > bytes.length) {
        throw new DeserializationError(`buffer too short: need ${len} bytes at offset ${offset}`);
    }
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

function toBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
}

function fromBase64(str: string): Uint8Array {
    return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

// =============================================================================
// Re-exports for issuer key persistence
// =============================================================================

export {
    ristretto255,
    generateParameters,
    keyGen,
    encodePublicKey,
    decodePublicKey,
    encodePrivateKey,
    decodePrivateKey,
    WebCryptoPRNG,
};

export type { SystemParams, PublicKey, PrivateKey, PRNG };
