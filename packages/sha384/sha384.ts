// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package sha384 implements SHA-2-384 cryptographic hash function.
 */

import { SHA512 } from "@stablelib/sha512";

export const DIGEST_LENGTH = 48;
export const BLOCK_SIZE = 128;

/**
 * SHA2-384 cryptographic hash algorithm.
 *
 * SHA-384 is the same algorithm as SHA-512, but with
 * different initialization vectors and digest length.
 */
export class SHA384 extends SHA512 {

    readonly digestLength = DIGEST_LENGTH;

    protected _initState() {
        this._stateHi[0] = 0xcbbb9d5d;
        this._stateHi[1] = 0x629a292a;
        this._stateHi[2] = 0x9159015a;
        this._stateHi[3] = 0x152fecd8;
        this._stateHi[4] = 0x67332667;
        this._stateHi[5] = 0x8eb44a87;
        this._stateHi[6] = 0xdb0c2e0d;
        this._stateHi[7] = 0x47b5481d;

        this._stateLo[0] = 0xc1059ed8;
        this._stateLo[1] = 0x367cd507;
        this._stateLo[2] = 0x3070dd17;
        this._stateLo[3] = 0xf70e5939;
        this._stateLo[4] = 0xffc00b31;
        this._stateLo[5] = 0x68581511;
        this._stateLo[6] = 0x64f98fa7;
        this._stateLo[7] = 0xbefa4fa4;
    }
}

export function hash(data: Uint8Array): Uint8Array {
    const h = new SHA384();
    h.update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}
