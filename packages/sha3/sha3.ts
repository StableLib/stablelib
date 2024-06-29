// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package sha3 implements SHA3 hash function and SHAKE extended output functions.
 */

// Based on Tiny-SHA3 implementation by Markku-Juhani O. Saarinen.
// https://github.com/mjosaarinen/tiny_sha3
//
// MIT License:
//
// Copyright (c) 2015 Markku-Juhani O. Saarinen
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import type { SerializableHash } from "@stablelib/hash";
import { readUint32LE, writeUint32LE } from "@stablelib/binary";
import { wipe } from "@stablelib/wipe";

export class Keccak {
    protected _sh = new Int32Array(25); // temporary space for permutation (high bits)
    protected _sl = new Int32Array(25); // temporary space for permutation (low bits)
    protected _state = new Uint8Array(200); // hash state
    protected _pos = 0; // position in state to XOR bytes into
    protected _finished = false; // whether the hash was finalized

    blockSize: number; // block size, which is also a sponge "rate"

    constructor(public capacity = 32) {
        if (capacity <= 0 || capacity > 128) {
            throw new Error("SHA3: incorrect capacity");
        }

        this.blockSize = 200 - capacity;
    }

    reset(): this {
        wipe(this._sh);
        wipe(this._sl);
        wipe(this._state);
        this._pos = 0;
        this._finished = false;
        return this;
    }

    clean = this.reset;

    update(data: Uint8Array): this {
        if (this._finished) {
            throw new Error("SHA3: can't update because hash was finished");
        }
        // XOR data into the "rate"-size part of state
        // (the rest is "capacity", which is not touched from outside).
        for (let i = 0; i < data.length; i++) {
            this._state[this._pos++] ^= data[i];

            // If the "rate" part is full, process the whole state
            // with Keccak permutation and reset position.
            if (this._pos >= this.blockSize) {
                keccakf(this._sh, this._sl, this._state);
                this._pos = 0;
            }
        }
        return this;
    }

    protected _padAndPermute(paddingByte: number): void {
        // Apply padding.
        this._state[this._pos] ^= paddingByte;
        this._state[this.blockSize - 1] ^= 0x80;

        // Permute state.
        keccakf(this._sh, this._sl, this._state);

        // Set finished flag to true.
        this._finished = true;
        this._pos = 0;
    }

    protected _squeeze(dst: Uint8Array): void {
        if (!this._finished) {
            throw new Error("SHA3: squeezing before padAndPermute");
        }
        // Squeeze.
        for (let i = 0; i < dst.length; i++) {
            if (this._pos === this.blockSize) {
                // Permute.
                keccakf(this._sh, this._sl, this._state);
                this._pos = 0;
            }
            dst[i] = this._state[this._pos++];
        }
    }
}

export class SHA3 extends Keccak implements SerializableHash {

    constructor(public digestLength = 32) {
        super(digestLength * 2);
    }

    finish(dst: Uint8Array): this {
        if (!this._finished) {
            this._padAndPermute(0x06);
        } else {
            // XXX: only works for up to blockSize digests,
            // which is the case in our implementation.
            this._pos = 0;
        }
        this._squeeze(dst);
        return this;
    }

    digest(): Uint8Array {
        let out = new Uint8Array(this.digestLength);
        this.finish(out);
        return out;
    }

    saveState(): SavedState {
        if (this._finished) {
            throw new Error("SHA3: cannot save finished state");
        }
        return new Uint8Array(this._state.subarray(0, this._pos));
    }

    restoreState(savedState: SavedState): this {
        this._state.set(savedState);
        this._pos = savedState.length;
        this._finished = false;
        return this;
    }

    cleanSavedState(savedState: SavedState) {
        wipe(savedState);
    }
}

export type SavedState = Uint8Array;

export class SHA3224 extends SHA3 {
    constructor() {
        super(224 / 8);
    }
}

export class SHA3256 extends SHA3 {
    constructor() {
        super(256 / 8);
    }
}

export class SHA3384 extends SHA3 {
    constructor() {
        super(384 / 8);
    }
}

export class SHA3512 extends SHA3 {
    constructor() {
        super(512 / 8);
    }
}

export function hash(digestLength: number, data: Uint8Array): Uint8Array {
    const h = new SHA3(digestLength);
    h.update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}

export const hash224 = (data: Uint8Array) => hash(224 / 8, data);
export const hash256 = (data: Uint8Array) => hash(256 / 8, data);
export const hash384 = (data: Uint8Array) => hash(384 / 8, data);
export const hash512 = (data: Uint8Array) => hash(512 / 8, data);

export class SHAKE extends Keccak {
    constructor(public bitSize: number) {
        super(bitSize / 8 * 2);
    }

    stream(dst: Uint8Array): void {
        if (!this._finished) {
            this._padAndPermute(0x1f);
        }
        this._squeeze(dst);
    }
}

export class SHAKE128 extends SHAKE {
    constructor() {
        super(128);
    }
}

export class SHAKE256 extends SHAKE {
    constructor() {
        super(256);
    }
}

const RNDC_HI = new Int32Array([
    0x00000000, 0x00000000, 0x80000000,
    0x80000000, 0x00000000, 0x00000000,
    0x80000000, 0x80000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x80000000, 0x80000000,
    0x80000000, 0x80000000, 0x80000000,
    0x00000000, 0x80000000, 0x80000000,
    0x80000000, 0x00000000, 0x80000000
]);

const RNDC_LO = new Int32Array([
    0x00000001, 0x00008082, 0x0000808a,
    0x80008000, 0x0000808b, 0x80000001,
    0x80008081, 0x00008009, 0x0000008a,
    0x00000088, 0x80008009, 0x8000000a,
    0x8000808b, 0x0000008b, 0x00008089,
    0x00008003, 0x00008002, 0x00000080,
    0x0000800a, 0x8000000a, 0x80008081,
    0x00008080, 0x80000001, 0x80008008
]);

function keccakf(sh: Int32Array, sl: Int32Array, buf: Uint8Array) {
    let bch0: number, bch1: number, bch2: number, bch3: number, bch4: number;
    let bcl0: number, bcl1: number, bcl2: number, bcl3: number, bcl4: number;
    let th: number, tl: number;

    for (let i = 0; i < 25; i++) {
        sl[i] = readUint32LE(buf, i * 8);
        sh[i] = readUint32LE(buf, i * 8 + 4);
    }

    for (let r = 0; r < 24; r++) {
        // Theta
        bch0 = sh[0] ^ sh[5] ^ sh[10] ^ sh[15] ^ sh[20];
        bch1 = sh[1] ^ sh[6] ^ sh[11] ^ sh[16] ^ sh[21];
        bch2 = sh[2] ^ sh[7] ^ sh[12] ^ sh[17] ^ sh[22];
        bch3 = sh[3] ^ sh[8] ^ sh[13] ^ sh[18] ^ sh[23];
        bch4 = sh[4] ^ sh[9] ^ sh[14] ^ sh[19] ^ sh[24];

        bcl0 = sl[0] ^ sl[5] ^ sl[10] ^ sl[15] ^ sl[20];
        bcl1 = sl[1] ^ sl[6] ^ sl[11] ^ sl[16] ^ sl[21];
        bcl2 = sl[2] ^ sl[7] ^ sl[12] ^ sl[17] ^ sl[22];
        bcl3 = sl[3] ^ sl[8] ^ sl[13] ^ sl[18] ^ sl[23];
        bcl4 = sl[4] ^ sl[9] ^ sl[14] ^ sl[19] ^ sl[24];

        th = bch4 ^ ((bch1 << 1) | (bcl1 >>> (32 - 1)));
        tl = bcl4 ^ ((bcl1 << 1) | (bch1 >>> (32 - 1)));

        sh[0] ^= th;
        sh[5] ^= th;
        sh[10] ^= th;
        sh[15] ^= th;
        sh[20] ^= th;

        sl[0] ^= tl;
        sl[5] ^= tl;
        sl[10] ^= tl;
        sl[15] ^= tl;
        sl[20] ^= tl;

        th = bch0 ^ ((bch2 << 1) | (bcl2 >>> (32 - 1)));
        tl = bcl0 ^ ((bcl2 << 1) | (bch2 >>> (32 - 1)));

        sh[1] ^= th;
        sh[6] ^= th;
        sh[11] ^= th;
        sh[16] ^= th;
        sh[21] ^= th;

        sl[1] ^= tl;
        sl[6] ^= tl;
        sl[11] ^= tl;
        sl[16] ^= tl;
        sl[21] ^= tl;

        th = bch1 ^ ((bch3 << 1) | (bcl3 >>> (32 - 1)));
        tl = bcl1 ^ ((bcl3 << 1) | (bch3 >>> (32 - 1)));

        sh[2] ^= th;
        sh[7] ^= th;
        sh[12] ^= th;
        sh[17] ^= th;
        sh[22] ^= th;

        sl[2] ^= tl;
        sl[7] ^= tl;
        sl[12] ^= tl;
        sl[17] ^= tl;
        sl[22] ^= tl;

        th = bch2 ^ ((bch4 << 1) | (bcl4 >>> (32 - 1)));
        tl = bcl2 ^ ((bcl4 << 1) | (bch4 >>> (32 - 1)));

        sh[3] ^= th; sl[3] ^= tl;
        sh[8] ^= th; sl[8] ^= tl;
        sh[13] ^= th; sl[13] ^= tl;
        sh[18] ^= th; sl[18] ^= tl;
        sh[23] ^= th; sl[23] ^= tl;

        th = bch3 ^ ((bch0 << 1) | (bcl0 >>> (32 - 1)));
        tl = bcl3 ^ ((bcl0 << 1) | (bch0 >>> (32 - 1)));

        sh[4] ^= th;
        sh[9] ^= th;
        sh[14] ^= th;
        sh[19] ^= th;
        sh[24] ^= th;

        sl[4] ^= tl;
        sl[9] ^= tl;
        sl[14] ^= tl;
        sl[19] ^= tl;
        sl[24] ^= tl;

        // Rho Pi
        th = sh[1];
        tl = sl[1];

        bch0 = sh[10];
        bcl0 = sl[10];
        sh[10] = (th << 1) | (tl >>> (32 - 1));
        sl[10] = (tl << 1) | (th >>> (32 - 1));
        th = bch0;
        tl = bcl0;

        bch0 = sh[7];
        bcl0 = sl[7];
        sh[7] = (th << 3) | (tl >>> (32 - 3));
        sl[7] = (tl << 3) | (th >>> (32 - 3));
        th = bch0;
        tl = bcl0;

        bch0 = sh[11];
        bcl0 = sl[11];
        sh[11] = (th << 6) | (tl >>> (32 - 6));
        sl[11] = (tl << 6) | (th >>> (32 - 6));
        th = bch0;
        tl = bcl0;

        bch0 = sh[17];
        bcl0 = sl[17];
        sh[17] = (th << 10) | (tl >>> (32 - 10));
        sl[17] = (tl << 10) | (th >>> (32 - 10));
        th = bch0;
        tl = bcl0;

        bch0 = sh[18];
        bcl0 = sl[18];
        sh[18] = (th << 15) | (tl >>> (32 - 15));
        sl[18] = (tl << 15) | (th >>> (32 - 15));
        th = bch0;
        tl = bcl0;

        bch0 = sh[3];
        bcl0 = sl[3];
        sh[3] = (th << 21) | (tl >>> (32 - 21));
        sl[3] = (tl << 21) | (th >>> (32 - 21));
        th = bch0;
        tl = bcl0;

        bch0 = sh[5];
        bcl0 = sl[5];
        sh[5] = (th << 28) | (tl >>> (32 - 28));
        sl[5] = (tl << 28) | (th >>> (32 - 28));
        th = bch0;
        tl = bcl0;

        bch0 = sh[16];
        bcl0 = sl[16];
        sh[16] = (tl << 4) | (th >>> (32 - 4));
        sl[16] = (th << 4) | (tl >>> (32 - 4));
        th = bch0;
        tl = bcl0;

        bch0 = sh[8];
        bcl0 = sl[8];
        sh[8] = (tl << 13) | (th >>> (32 - 13));
        sl[8] = (th << 13) | (tl >>> (32 - 13));
        th = bch0;
        tl = bcl0;

        bch0 = sh[21];
        bcl0 = sl[21];
        sh[21] = (tl << 23) | (th >>> (32 - 23));
        sl[21] = (th << 23) | (tl >>> (32 - 23));
        th = bch0;
        tl = bcl0;

        bch0 = sh[24];
        bcl0 = sl[24];
        sh[24] = (th << 2) | (tl >>> (32 - 2));
        sl[24] = (tl << 2) | (th >>> (32 - 2));
        th = bch0;
        tl = bcl0;

        bch0 = sh[4];
        bcl0 = sl[4];
        sh[4] = (th << 14) | (tl >>> (32 - 14));
        sl[4] = (tl << 14) | (th >>> (32 - 14));
        th = bch0;
        tl = bcl0;

        bch0 = sh[15];
        bcl0 = sl[15];
        sh[15] = (th << 27) | (tl >>> (32 - 27));
        sl[15] = (tl << 27) | (th >>> (32 - 27));
        th = bch0;
        tl = bcl0;

        bch0 = sh[23];
        bcl0 = sl[23];
        sh[23] = (tl << 9) | (th >>> (32 - 9));
        sl[23] = (th << 9) | (tl >>> (32 - 9));
        th = bch0;
        tl = bcl0;

        bch0 = sh[19];
        bcl0 = sl[19];
        sh[19] = (tl << 24) | (th >>> (32 - 24));
        sl[19] = (th << 24) | (tl >>> (32 - 24));
        th = bch0;
        tl = bcl0;

        bch0 = sh[13];
        bcl0 = sl[13];
        sh[13] = (th << 8) | (tl >>> (32 - 8));
        sl[13] = (tl << 8) | (th >>> (32 - 8));
        th = bch0;
        tl = bcl0;

        bch0 = sh[12];
        bcl0 = sl[12];
        sh[12] = (th << 25) | (tl >>> (32 - 25));
        sl[12] = (tl << 25) | (th >>> (32 - 25));
        th = bch0;
        tl = bcl0;

        bch0 = sh[2];
        bcl0 = sl[2];
        sh[2] = (tl << 11) | (th >>> (32 - 11));
        sl[2] = (th << 11) | (tl >>> (32 - 11));
        th = bch0;
        tl = bcl0;

        bch0 = sh[20];
        bcl0 = sl[20];
        sh[20] = (tl << 30) | (th >>> (32 - 30));
        sl[20] = (th << 30) | (tl >>> (32 - 30));
        th = bch0;
        tl = bcl0;

        bch0 = sh[14];
        bcl0 = sl[14];
        sh[14] = (th << 18) | (tl >>> (32 - 18));
        sl[14] = (tl << 18) | (th >>> (32 - 18));
        th = bch0;
        tl = bcl0;

        bch0 = sh[22];
        bcl0 = sl[22];
        sh[22] = (tl << 7) | (th >>> (32 - 7));
        sl[22] = (th << 7) | (tl >>> (32 - 7));
        th = bch0;
        tl = bcl0;

        bch0 = sh[9];
        bcl0 = sl[9];
        sh[9] = (tl << 29) | (th >>> (32 - 29));
        sl[9] = (th << 29) | (tl >>> (32 - 29));
        th = bch0;
        tl = bcl0;

        bch0 = sh[6];
        bcl0 = sl[6];
        sh[6] = (th << 20) | (tl >>> (32 - 20));
        sl[6] = (tl << 20) | (th >>> (32 - 20));
        th = bch0;
        tl = bcl0;

        bch0 = sh[1];
        bcl0 = sl[1];
        sh[1] = (tl << 12) | (th >>> (32 - 12));
        sl[1] = (th << 12) | (tl >>> (32 - 12));
        th = bch0;
        tl = bcl0;

        // Chi
        bch0 = sh[0];
        bch1 = sh[1];
        bch2 = sh[2];
        bch3 = sh[3];
        bch4 = sh[4];

        sh[0] ^= (~bch1) & bch2;
        sh[1] ^= (~bch2) & bch3;
        sh[2] ^= (~bch3) & bch4;
        sh[3] ^= (~bch4) & bch0;
        sh[4] ^= (~bch0) & bch1;

        bcl0 = sl[0];
        bcl1 = sl[1];
        bcl2 = sl[2];
        bcl3 = sl[3];
        bcl4 = sl[4];

        sl[0] ^= (~bcl1) & bcl2;
        sl[1] ^= (~bcl2) & bcl3;
        sl[2] ^= (~bcl3) & bcl4;
        sl[3] ^= (~bcl4) & bcl0;
        sl[4] ^= (~bcl0) & bcl1;

        bch0 = sh[5];
        bch1 = sh[6];
        bch2 = sh[7];
        bch3 = sh[8];
        bch4 = sh[9];

        sh[5] ^= (~bch1) & bch2;
        sh[6] ^= (~bch2) & bch3;
        sh[7] ^= (~bch3) & bch4;
        sh[8] ^= (~bch4) & bch0;
        sh[9] ^= (~bch0) & bch1;

        bcl0 = sl[5];
        bcl1 = sl[6];
        bcl2 = sl[7];
        bcl3 = sl[8];
        bcl4 = sl[9];

        sl[5] ^= (~bcl1) & bcl2;
        sl[6] ^= (~bcl2) & bcl3;
        sl[7] ^= (~bcl3) & bcl4;
        sl[8] ^= (~bcl4) & bcl0;
        sl[9] ^= (~bcl0) & bcl1;

        bch0 = sh[10];
        bch1 = sh[11];
        bch2 = sh[12];
        bch3 = sh[13];
        bch4 = sh[14];

        sh[10] ^= (~bch1) & bch2;
        sh[11] ^= (~bch2) & bch3;
        sh[12] ^= (~bch3) & bch4;
        sh[13] ^= (~bch4) & bch0;
        sh[14] ^= (~bch0) & bch1;

        bcl0 = sl[10];
        bcl1 = sl[11];
        bcl2 = sl[12];
        bcl3 = sl[13];
        bcl4 = sl[14];

        sl[10] ^= (~bcl1) & bcl2;
        sl[11] ^= (~bcl2) & bcl3;
        sl[12] ^= (~bcl3) & bcl4;
        sl[13] ^= (~bcl4) & bcl0;
        sl[14] ^= (~bcl0) & bcl1;

        bch0 = sh[15];
        bch1 = sh[16];
        bch2 = sh[17];
        bch3 = sh[18];
        bch4 = sh[19];

        sh[15] ^= (~bch1) & bch2;
        sh[16] ^= (~bch2) & bch3;
        sh[17] ^= (~bch3) & bch4;
        sh[18] ^= (~bch4) & bch0;
        sh[19] ^= (~bch0) & bch1;

        bcl0 = sl[15];
        bcl1 = sl[16];
        bcl2 = sl[17];
        bcl3 = sl[18];
        bcl4 = sl[19];

        sl[15] ^= (~bcl1) & bcl2;
        sl[16] ^= (~bcl2) & bcl3;
        sl[17] ^= (~bcl3) & bcl4;
        sl[18] ^= (~bcl4) & bcl0;
        sl[19] ^= (~bcl0) & bcl1;

        bch0 = sh[20];
        bch1 = sh[21];
        bch2 = sh[22];
        bch3 = sh[23];
        bch4 = sh[24];

        sh[20] ^= (~bch1) & bch2;
        sh[21] ^= (~bch2) & bch3;
        sh[22] ^= (~bch3) & bch4;
        sh[23] ^= (~bch4) & bch0;
        sh[24] ^= (~bch0) & bch1;

        bcl0 = sl[20];
        bcl1 = sl[21];
        bcl2 = sl[22];
        bcl3 = sl[23];
        bcl4 = sl[24];

        sl[20] ^= (~bcl1) & bcl2;
        sl[21] ^= (~bcl2) & bcl3;
        sl[22] ^= (~bcl3) & bcl4;
        sl[23] ^= (~bcl4) & bcl0;
        sl[24] ^= (~bcl0) & bcl1;

        //  Iota
        sh[0] ^= RNDC_HI[r];
        sl[0] ^= RNDC_LO[r];
    }

    for (let i = 0; i < 25; i++) {
        writeUint32LE(sl[i], buf, i * 8);
        writeUint32LE(sh[i], buf, i * 8 + 4);
    }
}
