// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import type { FinalizeData } from '@cloudflare/voprf-ts';
import {
    Evaluation,
    EvaluationRequest,
    Oprf,
    VOPRFClient,
    VOPRFServer,
    generateKeyPair,
    type DLEQParams,
    type Group,
    type SuiteID,
    type HashID,
    DLEQProof,
} from '@cloudflare/voprf-ts';
import {
    AuthenticatorInput,
    Token,
    TokenChallenge,
    type TokenTypeEntry,
} from './auth_scheme/private_token.js';
import { joinAll, readVarint, serialiseVarint } from './util.js';

export interface VOPRFExtraParams {
    suite: SuiteID;
    group: Group;
    Ne: number;
    Ns: number;
    Nk: number;
    hash: HashID;
    dleqParams: DLEQParams;
}

const VOPRF_SUITE = Oprf.Suite.RISTRETTO255_SHA512;
const VOPRF_GROUP = Oprf.getGroup(VOPRF_SUITE);
const VOPRF_HASH = Oprf.getHash(VOPRF_SUITE);
const VOPRF_EXTRA_PARAMS: VOPRFExtraParams = {
    suite: VOPRF_SUITE,
    group: VOPRF_GROUP,
    Ne: VOPRF_GROUP.eltSize(),
    Ns: VOPRF_GROUP.scalarSize(),
    Nk: Oprf.getOprfSize(VOPRF_SUITE),
    hash: VOPRF_HASH,
    dleqParams: {
        group: VOPRF_GROUP.id,
        hash: VOPRF_HASH,
        dst: new Uint8Array(),
    },
} as const;

// Token Type Entry Update:
//  - Token Type VOPRF (ristretto255, SHA-512)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-batched-tokens-04#name-token-type-voprf-p-384-sha-
export const VOPRF: Readonly<TokenTypeEntry> & VOPRFExtraParams = {
    value: 0x0005,
    name: 'VOPRF (ristretto255, SHA-512)',
    Nid: 32,
    publicVerifiable: false,
    publicMetadata: false,
    privateMetadata: false,
    ...VOPRF_EXTRA_PARAMS,
} as const;

export function keyGen(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    return generateKeyPair(VOPRF.suite);
}

async function getTokenKeyID(publicKey: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey));
}

export class BatchedTokenRequest {
    // struct {
    //     uint16_t token_type = 0x0001; /* Type VOPRF(P-384, SHA-384) */
    //     uint8_t truncated_token_key_id;
    //     uint8_t blinded_msg[Ne]<V>;
    //   } TokenRequest;

    tokenType: number;
    constructor(
        public readonly truncatedTokenKeyId: number,
        public readonly blindedMsgs: Uint8Array[],
    ) {
        for (const blindedMsg of blindedMsgs) {
            if (blindedMsg.length !== VOPRF.Ne) {
                throw new Error('blinded message has invalide size');
            }
        }

        this.tokenType = VOPRF.value;
    }

    static deserialize(bytes: Uint8Array): BatchedTokenRequest {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        if (type !== VOPRF.value) {
            throw new Error('mismatch of token type');
        }

        const truncatedTokenKeyId = input.getUint8(offset);
        offset += 1;

        const { value: length, usize } = readVarint(input, offset);
        offset += usize;

        const blindedMsgs: Uint8Array[] = [];
        const endBlindedMsgs = offset + length;
        for (offset; offset < endBlindedMsgs; offset += VOPRF.Ne) {
            const blindedMsg = new Uint8Array(input.buffer.slice(offset, offset + VOPRF.Ne));
            blindedMsgs.push(blindedMsg);
        }

        return new BatchedTokenRequest(truncatedTokenKeyId, blindedMsgs);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.truncatedTokenKeyId);
        output.push(b);

        let length = 0;
        const serializedBlindedMsgs = new Array<ArrayBufferLike>(this.blindedMsgs.length);
        for (let i = 0; i < this.blindedMsgs.length; i += 1) {
            const blindedMsg = this.blindedMsgs[i];
            length += blindedMsg.length;
            serializedBlindedMsgs[i] = blindedMsg.buffer;
        }

        output.push(serialiseVarint(length).buffer);
        for (const b of serializedBlindedMsgs) {
            output.push(b);
        }

        return new Uint8Array(joinAll(output));
    }
}

export class BatchedTokenResponse {
    // struct {
    //     uint8_t evaluate_msgs[Ne]<V>;
    //     uint8_t evaluate_proof[Ns+Ns];
    //  } TokenResponse;

    constructor(
        public readonly evaluateMsgs: Uint8Array[],
        public readonly evaluateProof: Uint8Array,
    ) {
        if (evaluateMsgs.length % VOPRF.Ne !== 0) {
            throw new Error('evaluate_msg has invalid size');
        }
        if (evaluateProof.length !== 2 * VOPRF.Ns) {
            throw new Error('evaluate_proof has invalid size');
        }
    }

    static deserialize(bytes: Uint8Array): BatchedTokenResponse {
        let offset = 0;
        let { value: len, usize } = readVarint(new DataView(bytes.buffer), offset);
        offset += usize;
        if (len % VOPRF.Ne !== 0) {
            throw new Error('evaludated_elements length is invalid');
        }
        const nElements = len / VOPRF.Ne;
        const evaluateMsgs = new Array(nElements);
        for (let i = 0; i < evaluateMsgs.length; i += 1) {
            const len = VOPRF.Ne;
            evaluateMsgs[i] = new Uint8Array(bytes.slice(offset, offset + len));
            offset += len;
        }

        len = 2 * VOPRF.Ns;
        const evaluateProof = new Uint8Array(bytes.slice(offset, offset + len));

        return new BatchedTokenResponse(evaluateMsgs, evaluateProof);
    }

    serialize(): Uint8Array {
        return new Uint8Array(
            joinAll([
                serialiseVarint(this.evaluateMsgs.length),
                ...this.evaluateMsgs,
                this.evaluateProof,
            ]),
        );
    }
}

export function verifyToken(token: Token, privateKeyIssuer: Uint8Array): Promise<boolean> {
    const vServer = new VOPRFServer(VOPRF.suite, privateKeyIssuer);
    const authInput = token.authInput.serialize();
    return vServer.verifyFinalize(authInput, token.authenticator);
}

export class Issuer {
    private vServer: VOPRFServer;

    constructor(
        public name: string,
        private privateKey: Uint8Array,
        public publicKey: Uint8Array,
    ) {
        this.vServer = new VOPRFServer(VOPRF.suite, this.privateKey);
    }

    async issue(tokReq: BatchedTokenRequest): Promise<BatchedTokenResponse> {
        const blindedElts = tokReq.blindedMsgs.map((b) => VOPRF.group.desElt(b));
        const evalReq = new EvaluationRequest(blindedElts);
        const evaluation = await this.vServer.blindEvaluate(evalReq);

        if (evaluation.evaluated.length !== 1) {
            throw new Error('evaluation is of a non-single element');
        }
        const evaluateMsgs = evaluation.evaluated.map((e) => e.serialize());

        if (typeof evaluation.proof === 'undefined') {
            throw new Error('evaluation has no DLEQ proof');
        }
        const evaluateProof = evaluation.proof.serialize();

        return new BatchedTokenResponse(evaluateMsgs, evaluateProof);
    }

    tokenKeyID(): Promise<Uint8Array> {
        return getTokenKeyID(this.publicKey);
    }

    verify(token: Token): Promise<boolean> {
        const authInput = token.authInput.serialize();
        return this.vServer.verifyFinalize(authInput, token.authenticator);
    }
}

export class Client {
    private finData?: {
        vClient: VOPRFClient;
        authInputs: AuthenticatorInput[];
        finData: FinalizeData;
    };

    async createTokenRequests(
        tokChl: TokenChallenge,
        issuerPublicKey: Uint8Array,
        amount: number,
    ): Promise<BatchedTokenRequest> {
        const tokenInputs: Uint8Array[] = new Array(amount);
        const authInputs: AuthenticatorInput[] = new Array(amount);

        const challengeDigest = new Uint8Array(
            await crypto.subtle.digest('SHA-256', tokChl.serialize()),
        );
        const tokenKeyId = await getTokenKeyID(issuerPublicKey);
        for (let i = 0; i < tokenInputs.length; i += 1) {
            const nonce = crypto.getRandomValues(new Uint8Array(32));

            const authInput = new AuthenticatorInput(
                VOPRF,
                VOPRF.value,
                nonce,
                challengeDigest,
                tokenKeyId,
            );
            tokenInputs[i] = authInput.serialize();
            authInputs[i] = authInput;
        }

        const vClient = new VOPRFClient(VOPRF.suite, issuerPublicKey);
        const [finData, evalReq] = await vClient.blind(tokenInputs);
        if (evalReq.blinded.length !== 1) {
            throw new Error('created a non-single blinded element');
        }
        const blindedMsgs = evalReq.blinded.map((e) => e.serialize());

        // "truncated_token_key_id" is the least significant byte of the
        // token_key_id in network byte order (in other words, the
        // last 8 bits of token_key_id).
        const truncatedTokenKeyId = tokenKeyId[tokenKeyId.length - 1];
        const tokenRequest = new BatchedTokenRequest(truncatedTokenKeyId, blindedMsgs);

        this.finData = { vClient, authInputs, finData };

        return tokenRequest;
    }

    deserializeTokenResponse(bytes: Uint8Array): BatchedTokenResponse {
        return BatchedTokenResponse.deserialize(bytes);
    }

    async finalize(tokRes: BatchedTokenResponse): Promise<Token[]> {
        if (!this.finData) {
            throw new Error('no token request was created yet');
        }

        const proof = DLEQProof.deserialize(VOPRF_GROUP.id, tokRes.evaluateProof);
        const evaluateMsgs = tokRes.evaluateMsgs.map((e) => VOPRF.group.desElt(e));
        const evaluation = new Evaluation(Oprf.Mode.VOPRF, evaluateMsgs, proof);
        const [authenticator] = await this.finData.vClient.finalize(
            this.finData.finData,
            evaluation,
        );
        const tokens = this.finData.authInputs.map(
            (input) => new Token(VOPRF, input, authenticator),
        );

        this.finData = undefined;

        return tokens;
    }
}

export class Origin {
    private tokenType = VOPRF;

    constructor(public readonly originInfo?: string[]) {}

    async verify(token: Token, privateKeyIssuer: Uint8Array): Promise<boolean> {
        const vServer = new VOPRFServer(VOPRF.suite, privateKeyIssuer);
        const authInput = token.authInput.serialize();
        return vServer.verifyFinalize(authInput, token.authenticator);
    }

    createTokenChallenge(issuerName: string, redemptionContext: Uint8Array): TokenChallenge {
        return new TokenChallenge(
            this.tokenType.value,
            issuerName,
            redemptionContext,
            this.originInfo,
        );
    }
}
