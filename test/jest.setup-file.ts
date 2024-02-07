// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Mocking crypto with NodeJS WebCrypto module only for tests.
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { webcrypto } from 'node:crypto';

const parentSign = webcrypto.subtle.sign;

// RSA-RAW is not supported by WebCrypto, so we need to mock it.
// Taken from cloudflare/blindrsa-ts https://github.com/cloudflare/blindrsa-ts/blob/b7a4c669620fba62ce736fe84445635e222d0d11/test/jest.setup-file.ts#L8-L32
async function mockSign(
    algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
    key: CryptoKey,
    data: Uint8Array,
): Promise<ArrayBuffer> {
    if (
        algorithm === 'RSA-RAW' ||
        (typeof algorithm !== 'string' && algorithm?.name === 'RSA-RAW')
    ) {
        const algorithmName = key.algorithm.name;
        if (algorithmName !== 'RSA-RAW') {
            throw new Error(`Invalid key algorithm: ${algorithmName}`);
        }
        key.algorithm.name = 'RSA-PSS';
        try {
            return RSABSSA.SHA384.PSSZero.Deterministic().blindSign(key, data);
        } finally {
            key.algorithm.name = algorithmName;
        }
    }

    // webcrypto calls crypto, which is mocked. We need to restore the original implementation.
    crypto.subtle.sign = parentSign;
    const res = webcrypto.subtle.sign(algorithm, key, data);
    crypto.subtle.sign = mockSign;
    return res;
}

if (typeof crypto === 'undefined') {
    Object.assign(global, { crypto: webcrypto });
}
crypto.subtle.sign = mockSign;
