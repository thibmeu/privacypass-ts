import { TOKEN_TYPES, tokenRequestToTokenTypeEntry } from './index.js';
import { TokenRequest as Type1TokenRequest } from './priv_verif_token.js';
import { TokenRequest as Type2TokenRequest } from './pub_verif_token.js';
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
            const blindedMsg = new Uint8Array(input.buffer.slice(offset, offset + len));
            offset += len;

            batchedTokenRequests.push(TokenRequest.deserialize(blindedMsg));
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
}
