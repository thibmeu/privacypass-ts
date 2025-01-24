import { TOKEN_TYPES, TokenChallenge, tokenRequestToTokenTypeEntry } from './index.js';
import {
    Client as Type1Client,
    Issuer as Type1Issuer,
    TokenRequest as Type1TokenRequest,
    TokenResponse as Type1TokenResponse,
} from './priv_verif_token.js';
import {
    Client as Type2Client,
    Issuer as Type2Issuer,
    TokenRequest as Type2TokenRequest,
    TokenResponse as Type2TokenResponse,
} from './pub_verif_token.js';
import { joinAll } from './util';

export class TokenRequest {
    // struct {
    //     uint16_t token_type;
    //     select (token_type) {
    //         case (0x0001): /* Type VOPRF(P-384, SHA-384), RFC 9578 */
    //             uint8_t truncated_token_key_id;
    //             uint8_t blinded_msg[Ne];
    //         case (0x0002): /* Type Blind RSA (2048-bit), RFC 9578 */
    //             uint8_t truncated_token_key_id;
    //             uint8_t blinded_msg[Nk];
    //     }
    // } TokenRequest;
    constructor(public readonly tokenRequest: Type1TokenRequest | Type2TokenRequest) {}

    static deserialize(bytes: Uint8Array): TokenRequest {
        const tokenTypeEntry = tokenRequestToTokenTypeEntry(bytes);

        switch (tokenTypeEntry.value) {
            case TOKEN_TYPES.VOPRF.value:
                return new TokenRequest(Type1TokenRequest.deserialize(bytes));
            case TOKEN_TYPES.BLIND_RSA.value:
                return new TokenRequest(Type2TokenRequest.deserialize(tokenTypeEntry, bytes));
            default:
                throw new Error('Token Type not supported');
        }
    }

    serialize(): Uint8Array {
        return this.tokenRequest.serialize();
    }

    get tokenType(): number {
        return this.tokenRequest.tokenType;
    }

    get truncatedTokenKeyId(): number {
        return this.tokenRequest.truncatedTokenKeyId;
    }

    get blindMsg(): Uint8Array {
        return this.tokenRequest.blindedMsg;
    }
}

export class BatchedTokenRequest {
    // struct {
    //     TokenRequest token_requests<0..2^16-1>;
    // } BatchTokenRequest

    constructor(public readonly tokenRequests: TokenRequest[]) {}

    static deserialize(bytes: Uint8Array): BatchedTokenRequest {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const length = input.getUint16(offset);
        offset += 2;

        if (length != bytes.length + offset) {
            throw new Error('provided bytes does not match its encoded length');
        }

        const batchedTokenRequests: TokenRequest[] = [];

        while (offset < bytes.length) {
            const len = input.getUint16(offset);
            offset += 2;
            const b = new Uint8Array(input.buffer.slice(offset, offset + len));
            offset += len;

            batchedTokenRequests.push(TokenRequest.deserialize(b));
        }

        return new BatchedTokenRequest(batchedTokenRequests);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let length = 0;
        for (const tokenRequest of this.tokenRequests) {
            const tokenRequestSerialized = tokenRequest.serialize();

            const b = new ArrayBuffer(2);
            new DataView(b).setUint16(0, tokenRequestSerialized.length);
            output.push(b);
            length += 2;

            output.push(tokenRequestSerialized);
            length += tokenRequestSerialized.length;
        }

        const b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, length);

        return new Uint8Array(joinAll([b, ...output]));
    }

    [Symbol.iterator](): Iterator<TokenRequest> {
        let index = 0;
        const data = this.tokenRequests;

        return {
            next(): IteratorResult<TokenRequest> {
                if (index < data.length) {
                    return { value: data[index++], done: false };
                } else {
                    return { value: undefined, done: true };
                }
            },
        };
    }
}

export class OptionalTokenResponse {
    // struct {
    //     TokenResponse token_response<0..2^16-1>; /* Defined by token_type */
    // } OptionalTokenResponse;
    constructor(public readonly tokenResponse: null | Uint8Array) {}

    static deserialize(bytes: Uint8Array): OptionalTokenResponse {
        if (bytes.length === 0) {
            return new OptionalTokenResponse(null);
        }
        return new OptionalTokenResponse(bytes);
    }

    serialize(): Uint8Array {
        if (this.tokenResponse === null) {
            return new Uint8Array();
        }
        return this.tokenResponse;
    }
}

// struct {
//     OptionalTokenResponse token_responses<0..2^16-1>;
// } BatchTokenResponse
export class BatchedTokenResponse {
    // struct {
    //     TokenRequest token_requests<0..2^16-1>;
    // } BatchTokenRequest
    constructor(public readonly tokenResponses: OptionalTokenResponse[]) {}

    static deserialize(bytes: Uint8Array): BatchedTokenResponse {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const length = input.getUint16(offset);
        offset += 2;

        if (length != bytes.length + offset) {
            throw new Error('provided bytes does not match its encoded length');
        }

        const batchedTokenResponses: OptionalTokenResponse[] = [];

        while (offset < bytes.length) {
            const len = input.getUint16(offset);
            offset += 2;
            const b = new Uint8Array(input.buffer.slice(offset, offset + len));
            offset += len;

            batchedTokenResponses.push(OptionalTokenResponse.deserialize(b));
        }

        return new BatchedTokenResponse(batchedTokenResponses);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let length = 0;
        for (const tokenResponse of this.tokenResponses) {
            const tokenResponseSerialized = tokenResponse.serialize();

            const b = new ArrayBuffer(2);
            new DataView(b).setUint16(0, tokenResponseSerialized.length);
            output.push(b);
            length += 2;

            output.push(tokenResponseSerialized);
            length += tokenResponseSerialized.length;
        }

        const b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, length);

        return new Uint8Array(joinAll([b, ...output]));
    }

    [Symbol.iterator](): Iterator<OptionalTokenResponse> {
        let index = 0;
        const data = this.tokenResponses;

        return {
            next(): IteratorResult<OptionalTokenResponse> {
                if (index < data.length) {
                    return { value: data[index++], done: false };
                } else {
                    return { value: undefined, done: true };
                }
            },
        };
    }
}

export class Issuer {
    private readonly issuers: { 1: Type1Issuer[]; 2: Type2Issuer[] };

    constructor(...issuers: (Type1Issuer | Type2Issuer)[]) {
        this.issuers = { 1: [], 2: [] };

        for (const issuer of issuers) {
            if (issuer instanceof Type1Issuer) {
                this.issuers[1].push(issuer);
            } else if (issuer instanceof Type2Issuer) {
                this.issuers[2].push(issuer);
            }
        }
    }

    async issue(tokenRequests: BatchedTokenRequest): Promise<BatchedTokenResponse> {
        const tokenResponses: OptionalTokenResponse[] = [];
        for (const tokenRequest of tokenRequests) {
            const issuers = this.issuers[tokenRequest.tokenType as 1 | 2];
            let issuer: undefined | Type1Issuer | Type2Issuer = undefined;
            for (const candidateIssuer of issuers) {
                // "truncated_token_key_id" is the least significant byte of the
                // token_key_id in network byte order (in other words, the
                // last 8 bits of token_key_id).
                const tokenKeyId = await candidateIssuer.tokenKeyID();
                const truncatedTokenKeyId = tokenKeyId[tokenKeyId.length - 1];
                if (truncatedTokenKeyId == tokenRequest.truncatedTokenKeyId) {
                    issuer = candidateIssuer;
                    break;
                }
            }
            if (issuer === undefined) {
                tokenResponses.push(new OptionalTokenResponse(null));
            } else {
                const response = (await issuer.issue(tokenRequest.tokenRequest)).serialize();
                tokenResponses.push(new OptionalTokenResponse(response));
            }
        }

        return new BatchedTokenResponse(tokenResponses);
    }

    tokenKeyIDs(tokenType: 1 | 2): Promise<Uint8Array[]> {
        // eslint-disable-next-line security/detect-object-injection
        return Promise.all(this.issuers[tokenType].map((issuer) => issuer.tokenKeyID()));
    }

    // TODO
    // verify(token: Token): Promise<boolean> {
    //     const authInput = token.authInput.serialize();
    //     return this.vServer.verifyFinalize(authInput, token.authenticator);
    // }
}

export class Client {
    async createTokenRequests(
        tokenChallenges: TokenChallenge[],
        issuerPublicKeys: Uint8Array[],
    ): Promise<BatchedTokenRequest> {
        if (tokenChallenges.length != issuerPublicKeys.length) {
            throw new Error('there should be one issuer public key per token challenges');
        }

        const promiseTokenRequests: Promise<TokenRequest>[] = [];
        for (const tokenChallenge of tokenChallenges) {
            switch (tokenChallenge.tokenType) {
                case TOKEN_TYPES.VOPRF.value:
                    promiseTokenRequests.push(
                        new Type1Client()
                            .createTokenRequest(tokenChallenge, issuerPublicKeys[0])
                            .then((t) => new TokenRequest(t)),
                    );
                    break;
                case TOKEN_TYPES.BLIND_RSA.value:
                    promiseTokenRequests.push(
                        new Type2Client()
                            .createTokenRequest(tokenChallenge, issuerPublicKeys[0])
                            .then((t) => new TokenRequest(t)),
                    );
                    break;
            }
        }
        const tokenRequests = await Promise.all(promiseTokenRequests);
        return new BatchedTokenRequest(tokenRequests);
    }

    deserializeTokenResponse(bytes: Uint8Array): BatchedTokenResponse {
        return BatchedTokenResponse.deserialize(bytes);
    }

    async finalize(tokenResponses: BatchedTokenResponse): Promise<Token[]> {}
}

export class Origin {
    constructor(public readonly originInfo?: string[]) {}

    // async verify(token: Token, publicKeyIssuer: CryptoKey): Promise<boolean> {
    //     return this.suite.verify(publicKeyIssuer, token.authenticator, token.authInput.serialize());
    // }

    // createTokenChallenge(issuerName: string, redemptionContext: Uint8Array): TokenChallenge {
    //     return new TokenChallenge(
    //         this.tokenType.value,
    //         issuerName,
    //         redemptionContext,
    //         this.originInfo,
    //     );
    // }
}
