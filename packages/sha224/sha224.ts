// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { SHA256 } from "@stablelib/sha256";

export const DIGEST_LENGTH = 28;
export const BLOCK_SIZE = 64;

/**
 * SHA2-224 cryptographic hash algorithm.
 *
 * SHA-224 is the same algorithm as SHA-256, but with
 * different initialization vectors and digest length.
 */
export class SHA224 extends SHA256 {

    readonly digestLength: number = DIGEST_LENGTH;

    protected _initState() {
        this._state[0] = 0xc1059ed8;
        this._state[1] = 0x367cd507;
        this._state[2] = 0x3070dd17;
        this._state[3] = 0xf70e5939;
        this._state[4] = 0xffc00b31;
        this._state[5] = 0x68581511;
        this._state[6] = 0x64f98fa7;
        this._state[7] = 0xbefa4fa4;
    }
}

export function hash(data: Uint8Array): Uint8Array {
    const h = new SHA224();
    h.update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}
