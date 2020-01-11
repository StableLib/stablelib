// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package salsa20 implements Salsa20 stream cipher.
 */

import { writeUint32LE } from "@stablelib/binary";
import { wipe } from "@stablelib/wipe";

// Number of Salsa20 rounds (Salsa20/20).
const ROUNDS = 20;

/**
 * Applies the Salsa20 core function to 16-byte input,
 * 32-byte key key, and puts the result into 64-byte array out.
 */
function core(out: Uint8Array, input: Uint8Array, key: Uint8Array): void {
    let j0 = 0x61707865; // "expa"
    let j1 = (key[3] << 24) | (key[2] << 16) | (key[1] << 8) | key[0];
    let j2 = (key[7] << 24) | (key[6] << 16) | (key[5] << 8) | key[4];
    let j3 = (key[11] << 24) | (key[10] << 16) | (key[9] << 8) | key[8];
    let j4 = (key[15] << 24) | (key[14] << 16) | (key[13] << 8) | key[12];
    let j5 = 0x3320646E; // "nd 3"
    let j6 = (input[3] << 24) | (input[2] << 16) | (input[1] << 8) | input[0];
    let j7 = (input[7] << 24) | (input[6] << 16) | (input[5] << 8) | input[4];
    let j8 = (input[11] << 24) | (input[10] << 16) | (input[9] << 8) | input[8];
    let j9 = (input[15] << 24) | (input[14] << 16) | (input[13] << 8) | input[12];
    let j10 = 0x79622D32; // "2-by"
    let j11 = (key[19] << 24) | (key[18] << 16) | (key[17] << 8) | key[16];
    let j12 = (key[23] << 24) | (key[22] << 16) | (key[21] << 8) | key[20];
    let j13 = (key[27] << 24) | (key[26] << 16) | (key[25] << 8) | key[24];
    let j14 = (key[31] << 24) | (key[30] << 16) | (key[29] << 8) | key[28];
    let j15 = 0x6B206574; // "te k"

    let x0 = j0;
    let x1 = j1;
    let x2 = j2;
    let x3 = j3;
    let x4 = j4;
    let x5 = j5;
    let x6 = j6;
    let x7 = j7;
    let x8 = j8;
    let x9 = j9;
    let x10 = j10;
    let x11 = j11;
    let x12 = j12;
    let x13 = j13;
    let x14 = j14;
    let x15 = j15;
    let u: number;

    for (let i = 0; i < ROUNDS; i += 2) {
        u = x0 + x12 | 0;
        x4 ^= u << 7 | u >>> (32 - 7);
        u = x4 + x0 | 0;
        x8 ^= u << 9 | u >>> (32 - 9);
        u = x8 + x4 | 0;
        x12 ^= u << 13 | u >>> (32 - 13);
        u = x12 + x8 | 0;
        x0 ^= u << 18 | u >>> (32 - 18);

        u = x5 + x1 | 0;
        x9 ^= u << 7 | u >>> (32 - 7);
        u = x9 + x5 | 0;
        x13 ^= u << 9 | u >>> (32 - 9);
        u = x13 + x9 | 0;
        x1 ^= u << 13 | u >>> (32 - 13);
        u = x1 + x13 | 0;
        x5 ^= u << 18 | u >>> (32 - 18);

        u = x10 + x6 | 0;
        x14 ^= u << 7 | u >>> (32 - 7);
        u = x14 + x10 | 0;
        x2 ^= u << 9 | u >>> (32 - 9);
        u = x2 + x14 | 0;
        x6 ^= u << 13 | u >>> (32 - 13);
        u = x6 + x2 | 0;
        x10 ^= u << 18 | u >>> (32 - 18);

        u = x15 + x11 | 0;
        x3 ^= u << 7 | u >>> (32 - 7);
        u = x3 + x15 | 0;
        x7 ^= u << 9 | u >>> (32 - 9);
        u = x7 + x3 | 0;
        x11 ^= u << 13 | u >>> (32 - 13);
        u = x11 + x7 | 0;
        x15 ^= u << 18 | u >>> (32 - 18);

        u = x0 + x3 | 0;
        x1 ^= u << 7 | u >>> (32 - 7);
        u = x1 + x0 | 0;
        x2 ^= u << 9 | u >>> (32 - 9);
        u = x2 + x1 | 0;
        x3 ^= u << 13 | u >>> (32 - 13);
        u = x3 + x2 | 0;
        x0 ^= u << 18 | u >>> (32 - 18);

        u = x5 + x4 | 0;
        x6 ^= u << 7 | u >>> (32 - 7);
        u = x6 + x5 | 0;
        x7 ^= u << 9 | u >>> (32 - 9);
        u = x7 + x6 | 0;
        x4 ^= u << 13 | u >>> (32 - 13);
        u = x4 + x7 | 0;
        x5 ^= u << 18 | u >>> (32 - 18);

        u = x10 + x9 | 0;
        x11 ^= u << 7 | u >>> (32 - 7);
        u = x11 + x10 | 0;
        x8 ^= u << 9 | u >>> (32 - 9);
        u = x8 + x11 | 0;
        x9 ^= u << 13 | u >>> (32 - 13);
        u = x9 + x8 | 0;
        x10 ^= u << 18 | u >>> (32 - 18);

        u = x15 + x14 | 0;
        x12 ^= u << 7 | u >>> (32 - 7);
        u = x12 + x15 | 0;
        x13 ^= u << 9 | u >>> (32 - 9);
        u = x13 + x12 | 0;
        x14 ^= u << 13 | u >>> (32 - 13);
        u = x14 + x13 | 0;
        x15 ^= u << 18 | u >>> (32 - 18);
    }
    writeUint32LE(x0 + j0 | 0, out, 0);
    writeUint32LE(x1 + j1 | 0, out, 4);
    writeUint32LE(x2 + j2 | 0, out, 8);
    writeUint32LE(x3 + j3 | 0, out, 12);
    writeUint32LE(x4 + j4 | 0, out, 16);
    writeUint32LE(x5 + j5 | 0, out, 20);
    writeUint32LE(x6 + j6 | 0, out, 24);
    writeUint32LE(x7 + j7 | 0, out, 28);
    writeUint32LE(x8 + j8 | 0, out, 32);
    writeUint32LE(x9 + j9 | 0, out, 36);
    writeUint32LE(x10 + j10 | 0, out, 40);
    writeUint32LE(x11 + j11 | 0, out, 44);
    writeUint32LE(x12 + j12 | 0, out, 48);
    writeUint32LE(x13 + j13 | 0, out, 52);
    writeUint32LE(x14 + j14 | 0, out, 56);
    writeUint32LE(x15 + j15 | 0, out, 60);
}

/**
 * Encrypt src with Salsa20/20 stream generated for the given 32-byte key
 * and 8-byte and write the result into dst and return it.
 *
 * dst and src may be the same, but otherwise must not overlap.
 *
 * Never use the same key and nonce to encrypt more than one message.
 *
 * If nonceInplaceCounterLength is not 0, the nonce is assumed to be a 16-byte
 * array with stream counter in first nonceInplaceCounterLength bytes and nonce
 * in the last remaining bytes. The counter will be incremented inplace for
 * each Salsa20 block. This is useful if you need to encrypt one stream of data
 * in chunks.
 */
export function streamXOR(key: Uint8Array, nonce: Uint8Array,
    src: Uint8Array, dst: Uint8Array, nonceInplaceCounterLength = 0): Uint8Array {
    // We only support 256-bit keys.
    if (key.length !== 32) {
        throw new Error("Salsa20: key size must be 32 bytes");
    }

    if (dst.length < src.length) {
        throw new Error("Salsa20: destination is shorter than source");
    }

    let nc: Uint8Array;
    let counterStart: number;

    if (nonceInplaceCounterLength === 0) {
        if (nonce.length !== 8) {
            throw new Error("Salsa20 nonce must be 8 bytes");
        }
        nc = new Uint8Array(16);
        // First bytes of nc are nonce, set it.
        nc.set(nonce);
        // Last bytes are counter.
        counterStart = nonce.length;
    } else {
        if (nonce.length !== 16) {
            throw new Error("Salsa20 nonce with counter must be 16 bytes");
        }
        // This will update passed nonce with counter inplace.
        nc = nonce;
        counterStart = 16 - nonceInplaceCounterLength;
    }

    // Allocate temporary space for Salsa20 block.
    const block = new Uint8Array(64);

    for (let i = 0; i < src.length; i += 64) {
        // Generate a block.
        core(block, nc, key);

        // XOR block bytes with src into dst.
        for (let j = i; j < i + 64 && j < src.length; j++) {
            dst[j] = src[j] ^ block[j - i];
        }

        // Increment counter.
        incrementCounter(nc, counterStart, nc.length - counterStart);
    }

    // Cleanup temporary space.
    wipe(block);

    if (nonceInplaceCounterLength === 0) {
        // Cleanup counter.
        wipe(nc);
    }

    return dst;
}

/**
 * Generate Salsa20/20 stream for the given 32-byte key and 8-byte nonce
 * and write it into dst and return it.
 *
 * Never use the same key and nonce to generate more than one stream.
 *
 * If nonceInplaceCounterLength is not 0, it behaves the same
 * with respect to the nonce as described in streamXOR documentation.
 *
 * stream is like streamXOR with all-zero src.
 */
export function stream(key: Uint8Array, nonce: Uint8Array,
    dst: Uint8Array, nonceInplaceCounterLength = 0): Uint8Array {
    wipe(dst);
    return streamXOR(key, nonce, dst, dst, nonceInplaceCounterLength);
}

function incrementCounter(counter: Uint8Array, pos: number, len: number) {
    let carry = 1;
    while (len--) {
        carry = carry + (counter[pos] & 0xff) | 0;
        counter[pos] = carry & 0xff;
        carry >>>= 8;
        pos++;
    }
    if (carry > 0) {
        throw new Error("Salsa20: counter overflow");
    }
}
