// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package sha512_256 implements SHA-2-512/256 cryptographic hash function.
 */

import { SHA512 } from "@stablelib/sha512";

export const DIGEST_LENGTH = 32;
export const BLOCK_SIZE = 128;

/**
 * SHA2-512/256 cryptographic hash algorithm.
 *
 * SHA-512/256 is the same algorithm as SHA-512, but with
 * different initialization vectors and digest length.
 */
// eslint:disable-next-line
export class SHA512_256 extends SHA512 {

    readonly digestLength = DIGEST_LENGTH;

    protected _initState() {
        this._stateHi[0] = 0x22312194;
        this._stateHi[1] = 0x9f555fa3;
        this._stateHi[2] = 0x2393b86b;
        this._stateHi[3] = 0x96387719;
        this._stateHi[4] = 0x96283ee2;
        this._stateHi[5] = 0xbe5e1e25;
        this._stateHi[6] = 0x2b0199fc;
        this._stateHi[7] = 0x0eb72ddc;

        this._stateLo[0] = 0xfc2bf72c;
        this._stateLo[1] = 0xc84c64c2;
        this._stateLo[2] = 0x6f53b151;
        this._stateLo[3] = 0x5940eabd;
        this._stateLo[4] = 0xa88effe3;
        this._stateLo[5] = 0x53863992;
        this._stateLo[6] = 0x2c85b8aa;
        this._stateLo[7] = 0x81c52ca2;
    }
}

export function hash(data: Uint8Array): Uint8Array {
    const h = new SHA512_256();
    h.update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}
