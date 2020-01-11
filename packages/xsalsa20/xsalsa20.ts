// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package xsalsa20 implements XSalsa20 stream cipher.
 */

import { writeUint32LE } from "@stablelib/binary";
import { streamXOR as salsaStreamXOR } from "@stablelib/salsa20";
import { wipe } from "@stablelib/wipe";

/**
 * Encrypt src with Salsa20/20 stream generated for the given 32-byte key
 * and 24-byte and write the result into dst and return it.
 *
 * dst and src may be the same, but otherwise must not overlap.
 *
 * Never use the same key and nonce to encrypt more than one message.
 */
export function streamXOR(key: Uint8Array, nonce: Uint8Array, src: Uint8Array,
    dst: Uint8Array, nonceInplaceCounterLength = 0): Uint8Array {

    if (nonceInplaceCounterLength === 0) {
        if (nonce.length !== 24) {
            throw new Error("XSalsa20 nonce must be 24 bytes");
        }
    } else {
        if (nonce.length !== 32) {
            throw new Error("XSalsa20 nonce with counter must be 32 bytes");
        }
    }

    // Use HSalsa one-way function to transform first 16 bytes of
    // 24-byte extended nonce and key into a new key for Salsa
    // stream -- "subkey".
    const subkey = hsalsa(key, nonce.subarray(0, 16), new Uint8Array(32));

    // Use last 8 bytes of 24-byte extended nonce as an actual nonce,
    // and a subkey derived in the previous step as key to encrypt.
    //
    // If nonceInplaceCounterLength > 0, we'll still pass the correct
    // nonce || counter, as we don't limit the end of nonce subarray.
    const result = salsaStreamXOR(subkey, nonce.subarray(16), src, dst,
        nonceInplaceCounterLength);

    // Clean subkey.
    wipe(subkey);

    return result;
}

/**
 * Generate Salsa20/20 stream for the given 32-byte key and
 * 24-byte nonce and write it into dst and return it.
 *
 * Never use the same key and nonce to generate more than one stream.
 *
 * stream is like streamXOR with all-zero src.
 */
export function stream(key: Uint8Array, nonce: Uint8Array, dst: Uint8Array,
    nonceInplaceCounterLength = 0): Uint8Array {

    wipe(dst);
    return streamXOR(key, nonce, dst, dst, nonceInplaceCounterLength);
}

// Number of Salsa20 rounds (Salsa20/20).
const ROUNDS = 20;

/**
 * HSalsa20 is a one-way function used in XSalsa20 to extend nonce,
 * and in NaCl to hash X25519 shared keys. It takes 32-byte key and
 * 16-byte src and writes 32-byte result into dst and returns it.
 */
export function hsalsa(key: Uint8Array, src: Uint8Array, dst: Uint8Array): Uint8Array {
    let x0 = 0x61707865; // "expa"
    let x1 = (key[3] << 24) | (key[2] << 16) | (key[1] << 8) | key[0];
    let x2 = (key[7] << 24) | (key[6] << 16) | (key[5] << 8) | key[4];
    let x3 = (key[11] << 24) | (key[10] << 16) | (key[9] << 8) | key[8];
    let x4 = (key[15] << 24) | (key[14] << 16) | (key[13] << 8) | key[12];
    let x5 = 0x3320646E; // "nd 3"
    let x6 = (src[3] << 24) | (src[2] << 16) | (src[1] << 8) | src[0];
    let x7 = (src[7] << 24) | (src[6] << 16) | (src[5] << 8) | src[4];
    let x8 = (src[11] << 24) | (src[10] << 16) | (src[9] << 8) | src[8];
    let x9 = (src[15] << 24) | (src[14] << 16) | (src[13] << 8) | src[12];
    let x10 = 0x79622D32; // "2-by"
    let x11 = (key[19] << 24) | (key[18] << 16) | (key[17] << 8) | key[16];
    let x12 = (key[23] << 24) | (key[22] << 16) | (key[21] << 8) | key[20];
    let x13 = (key[27] << 24) | (key[26] << 16) | (key[25] << 8) | key[24];
    let x14 = (key[31] << 24) | (key[30] << 16) | (key[29] << 8) | key[28];
    let x15 = 0x6B206574; // "te k"

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
    writeUint32LE(x0, dst, 0);
    writeUint32LE(x5, dst, 4);
    writeUint32LE(x10, dst, 8);
    writeUint32LE(x15, dst, 12);
    writeUint32LE(x6, dst, 16);
    writeUint32LE(x7, dst, 20);
    writeUint32LE(x8, dst, 24);
    writeUint32LE(x9, dst, 28);
    return dst;
}
