// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { deriveKey as pbkdf2 } from "@stablelib/pbkdf2";
import { SHA256 } from "@stablelib/sha256";
import { isInteger } from "@stablelib/int";
import { readUint32LE, writeUint32LE } from "@stablelib/binary";
import { wipe } from "@stablelib/wipe";

/**
 * Derives a key from password and salt with parameters
 * N — CPU/memory cost, r — block size, p — parallelization,
 * containing dkLen bytes.
 */
export function deriveKey(password: Uint8Array, salt: Uint8Array,
    N: number, r: number, p: number, dkLen: number): Promise<Uint8Array> {

    return new Promise<Uint8Array>((resolve) => {
        // Check parallelization parameter.
        if (p <= 0) {
            throw new Error("scrypt: incorrect p");
        }

        // Check r parameter.
        if (r <= 0) {
            throw new Error("scrypt: incorrect r");
        }

        // Check that N is within supported range.
        if (N < 1 || N > Math.pow(2, 31)) {
            throw new Error('scrypt: N must be between 2 and 2^31');
        }

        // Check that N is a power of two.
        if (!isInteger(N) || (N & (N - 1)) !== 0) {
            throw new Error("scrypt: N must be a power of 2");
        }

        const MAX_INT = (1 << 31) >>> 0;

        if (r * p >= 1 << 30 || r > MAX_INT / 128 / p || r > MAX_INT / 256 || N > MAX_INT / 128 / r) {
            throw new Error("scrypt: parameters are too large");
        }

        // XXX we can use Uint32Array, but Int32Array is faster, especially in Safari.
        const XY = new Int32Array(64 * r);
        const V = new Int32Array(32 * N * r);

        let B = pbkdf2(SHA256, password, salt, 1, p * 128 * r);

        for (let i = 0; i < p; i++) {
            smix(B.subarray(i * 128 * r), r, N, V, XY);
        }

        const result = pbkdf2(SHA256, password, B, 1, dkLen);

        // Wipe state.
        wipe(B);
        wipe(XY);
        wipe(V);

        resolve(result);
    });
}


function smix(B: Uint8Array, r: number, N: number, V: Int32Array, XY: Int32Array) {
    const xi = 0;
    const yi = 32 * r;
    const tmp = new Int32Array(16);

    for (let i = 0; i < 32 * r; i++) {
        XY[xi + i] = readUint32LE(B, i * 4);
    }
    for (let i = 0; i < N; i += 2) {
        blockCopy(V, i * (32 * r), XY, xi, 32 * r);
        blockMix(tmp, XY, xi, yi, r);

        blockCopy(V, (i + 1) * (32 * r), XY, yi, 32 * r);
        blockMix(tmp, XY, yi, xi, r);
    }
    for (let i = 0; i < N; i += 2) {
        let j = integerify(XY, xi, r) & (N - 1);
        blockXOR(XY, xi, V, j * (32 * r), 32 * r);
        blockMix(tmp, XY, xi, yi, r);

        j = integerify(XY, yi, r) & (N - 1);
        blockXOR(XY, yi, V, j * (32 * r), 32 * r);
        blockMix(tmp, XY, yi, xi, r);
    }
    for (let i = 0; i < 32 * r; i++) {
        writeUint32LE(XY[xi + i], B, i * 4);
    }

    wipe(tmp);
}


function salsaXOR(tmp: Int32Array, B: Int32Array, bin: number, bout: number) {
    const j0 = tmp[0] ^ B[bin++],
        j1 = tmp[1] ^ B[bin++],
        j2 = tmp[2] ^ B[bin++],
        j3 = tmp[3] ^ B[bin++],
        j4 = tmp[4] ^ B[bin++],
        j5 = tmp[5] ^ B[bin++],
        j6 = tmp[6] ^ B[bin++],
        j7 = tmp[7] ^ B[bin++],
        j8 = tmp[8] ^ B[bin++],
        j9 = tmp[9] ^ B[bin++],
        j10 = tmp[10] ^ B[bin++],
        j11 = tmp[11] ^ B[bin++],
        j12 = tmp[12] ^ B[bin++],
        j13 = tmp[13] ^ B[bin++],
        j14 = tmp[14] ^ B[bin++],
        j15 = tmp[15] ^ B[bin++];

    let x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
        x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
        x15 = j15;

    let u: number;
    for (let i = 0; i < 8; i += 2) {
        u = x0 + x12; x4 ^= u << 7 | u >>> (32 - 7);
        u = x4 + x0; x8 ^= u << 9 | u >>> (32 - 9);
        u = x8 + x4; x12 ^= u << 13 | u >>> (32 - 13);
        u = x12 + x8; x0 ^= u << 18 | u >>> (32 - 18);

        u = x5 + x1; x9 ^= u << 7 | u >>> (32 - 7);
        u = x9 + x5; x13 ^= u << 9 | u >>> (32 - 9);
        u = x13 + x9; x1 ^= u << 13 | u >>> (32 - 13);
        u = x1 + x13; x5 ^= u << 18 | u >>> (32 - 18);

        u = x10 + x6; x14 ^= u << 7 | u >>> (32 - 7);
        u = x14 + x10; x2 ^= u << 9 | u >>> (32 - 9);
        u = x2 + x14; x6 ^= u << 13 | u >>> (32 - 13);
        u = x6 + x2; x10 ^= u << 18 | u >>> (32 - 18);

        u = x15 + x11; x3 ^= u << 7 | u >>> (32 - 7);
        u = x3 + x15; x7 ^= u << 9 | u >>> (32 - 9);
        u = x7 + x3; x11 ^= u << 13 | u >>> (32 - 13);
        u = x11 + x7; x15 ^= u << 18 | u >>> (32 - 18);

        u = x0 + x3; x1 ^= u << 7 | u >>> (32 - 7);
        u = x1 + x0; x2 ^= u << 9 | u >>> (32 - 9);
        u = x2 + x1; x3 ^= u << 13 | u >>> (32 - 13);
        u = x3 + x2; x0 ^= u << 18 | u >>> (32 - 18);

        u = x5 + x4; x6 ^= u << 7 | u >>> (32 - 7);
        u = x6 + x5; x7 ^= u << 9 | u >>> (32 - 9);
        u = x7 + x6; x4 ^= u << 13 | u >>> (32 - 13);
        u = x4 + x7; x5 ^= u << 18 | u >>> (32 - 18);

        u = x10 + x9; x11 ^= u << 7 | u >>> (32 - 7);
        u = x11 + x10; x8 ^= u << 9 | u >>> (32 - 9);
        u = x8 + x11; x9 ^= u << 13 | u >>> (32 - 13);
        u = x9 + x8; x10 ^= u << 18 | u >>> (32 - 18);

        u = x15 + x14; x12 ^= u << 7 | u >>> (32 - 7);
        u = x12 + x15; x13 ^= u << 9 | u >>> (32 - 9);
        u = x13 + x12; x14 ^= u << 13 | u >>> (32 - 13);
        u = x14 + x13; x15 ^= u << 18 | u >>> (32 - 18);
    }

    B[bout++] = tmp[0] = (x0 + j0) | 0;
    B[bout++] = tmp[1] = (x1 + j1) | 0;
    B[bout++] = tmp[2] = (x2 + j2) | 0;
    B[bout++] = tmp[3] = (x3 + j3) | 0;
    B[bout++] = tmp[4] = (x4 + j4) | 0;
    B[bout++] = tmp[5] = (x5 + j5) | 0;
    B[bout++] = tmp[6] = (x6 + j6) | 0;
    B[bout++] = tmp[7] = (x7 + j7) | 0;
    B[bout++] = tmp[8] = (x8 + j8) | 0;
    B[bout++] = tmp[9] = (x9 + j9) | 0;
    B[bout++] = tmp[10] = (x10 + j10) | 0;
    B[bout++] = tmp[11] = (x11 + j11) | 0;
    B[bout++] = tmp[12] = (x12 + j12) | 0;
    B[bout++] = tmp[13] = (x13 + j13) | 0;
    B[bout++] = tmp[14] = (x14 + j14) | 0;
    B[bout++] = tmp[15] = (x15 + j15) | 0;
}

function blockCopy(dst: Int32Array, di: number, src: Int32Array, si: number, len: number) {
    while (len--) {
        dst[di++] = src[si++];
    }
}

function blockXOR(dst: Int32Array, di: number, src: Int32Array, si: number, len: number) {
    while (len--) {
        dst[di++] ^= src[si++];
    }
}

function blockMix(tmp: Int32Array, B: Int32Array, bin: number, bout: number, r: number) {
    blockCopy(tmp, 0, B, bin + (2 * r - 1) * 16, 16);
    for (let i = 0; i < 2 * r; i += 2) {
        salsaXOR(tmp, B, bin + i * 16, bout + i * 8);
        salsaXOR(tmp, B, bin + i * 16 + 16, bout + i * 8 + r * 16);
    }
}

function integerify(B: Int32Array, bi: number, r: number) {
    return B[bi + (2 * r - 1) * 16];
}
