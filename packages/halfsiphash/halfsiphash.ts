// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { readUint32LE, writeUint32LE } from "@stablelib/binary";
import { add, rotl } from "@stablelib/int";

export const KEY_LENGTH = 8;
export const DIGEST_LENGTH = 4;

/**
 * HalfSipHash-2-4 is an _experimental_ PRF which accepts 64-bit key
 * and variable-length data and returns 32-bit tag.
 *
 * It is suitable as a hash function for hash tables (using a random
 * per-table seed as key) to protect against hash-flooding DoS attacks.
 * It can also be used as a fast checksum with a fixed key.
 *
 * Do not use it for other cryptographic authentication purposes,
 * since 64-bit key is too small for that!
 *
 * HalfSipHash was created by Jean-Philippe Aumasson.
 */
export function halfSipHash(key: Uint8Array, data: Uint8Array): Uint8Array {
    if (key.length !== KEY_LENGTH) {
        throw new Error("halfSipHash: incorrect key length");
    }
    const k0 = readUint32LE(key, 0);
    const k1 = readUint32LE(key, 4);
    return writeUint32LE(halfSipHashNum(k0, k1, data));
}

/**
 * halfSipHashNum is like halfSipHash, but accepts key as two 32-bit unsigned
 * integers and returns a 32-bit unsigned integer result.
 */
export function halfSipHashNum(k0: number, k1: number, data: Uint8Array): number {
    let v0 = k0;
    let v1 = k1;
    let v2 = k0 ^ 0x6c796765;
    let v3 = k1 ^ 0x74656462;

    let pos = 0;
    let len = data.length;
    let fin = (len % 256) << 24; // final message block, includes length modulo 256

    // Compress full blocks.
    while (len >= 4) {
        const m = readUint32LE(data, pos);

        v3 ^= m;

        // Round 1
        v0 = add(v0, v1);
        v1 = rotl(v1, 5);
        v1 ^= v0;
        v0 = rotl(v0, 16);
        v2 = add(v2, v3);
        v3 = rotl(v3, 8);
        v3 ^= v2;
        v0 = add(v0, v3);
        v3 = rotl(v3, 7);
        v3 ^= v0;
        v2 = add(v2, v1);
        v1 = rotl(v1, 13);
        v1 ^= v2;
        v2 = rotl(v2, 16);

        // Round 2
        v0 = add(v0, v1);
        v1 = rotl(v1, 5);
        v1 ^= v0;
        v0 = rotl(v0, 16);
        v2 = add(v2, v3);
        v3 = rotl(v3, 8);
        v3 ^= v2;
        v0 = add(v0, v3);
        v3 = rotl(v3, 7);
        v3 ^= v0;
        v2 = add(v2, v1);
        v1 = rotl(v1, 13);
        v1 ^= v2;
        v2 = rotl(v2, 16);

        v0 ^= m;

        pos += 4;
        len -= 4;
    }

    // Compress last block.
    switch (len) {
        case 3:
            fin |= data[pos + 2] << 16;
        /* falls through */
        case 2:
            fin |= data[pos + 1] << 8;
        /* falls through */
        case 1:
            fin |= data[pos];
    }

    v3 ^= fin;

    // Round 1
    v0 = add(v0, v1);
    v1 = rotl(v1, 5);
    v1 ^= v0;
    v0 = rotl(v0, 16);
    v2 = add(v2, v3);
    v3 = rotl(v3, 8);
    v3 ^= v2;
    v0 = add(v0, v3);
    v3 = rotl(v3, 7);
    v3 ^= v0;
    v2 = add(v2, v1);
    v1 = rotl(v1, 13);
    v1 ^= v2;
    v2 = rotl(v2, 16);

    // Round 2
    v0 = add(v0, v1);
    v1 = rotl(v1, 5);
    v1 ^= v0;
    v0 = rotl(v0, 16);
    v2 = add(v2, v3);
    v3 = rotl(v3, 8);
    v3 ^= v2;
    v0 = add(v0, v3);
    v3 = rotl(v3, 7);
    v3 ^= v0;
    v2 = add(v2, v1);
    v1 = rotl(v1, 13);
    v1 ^= v2;
    v2 = rotl(v2, 16);

    v0 ^= fin;

    // Finalize
    v2 ^= 0xff;

    // Round 1
    v0 = add(v0, v1);
    v1 = rotl(v1, 5);
    v1 ^= v0;
    v0 = rotl(v0, 16);
    v2 = add(v2, v3);
    v3 = rotl(v3, 8);
    v3 ^= v2;
    v0 = add(v0, v3);
    v3 = rotl(v3, 7);
    v3 ^= v0;
    v2 = add(v2, v1);
    v1 = rotl(v1, 13);
    v1 ^= v2;
    v2 = rotl(v2, 16);

    // Round 2
    v0 = add(v0, v1);
    v1 = rotl(v1, 5);
    v1 ^= v0;
    v0 = rotl(v0, 16);
    v2 = add(v2, v3);
    v3 = rotl(v3, 8);
    v3 ^= v2;
    v0 = add(v0, v3);
    v3 = rotl(v3, 7);
    v3 ^= v0;
    v2 = add(v2, v1);
    v1 = rotl(v1, 13);
    v1 ^= v2;
    v2 = rotl(v2, 16);

    // Round 3
    v0 = add(v0, v1);
    v1 = rotl(v1, 5);
    v1 ^= v0;
    v0 = rotl(v0, 16);
    v2 = add(v2, v3);
    v3 = rotl(v3, 8);
    v3 ^= v2;
    v0 = add(v0, v3);
    v3 = rotl(v3, 7);
    v3 ^= v0;
    v2 = add(v2, v1);
    v1 = rotl(v1, 13);
    v1 ^= v2;
    v2 = rotl(v2, 16);

    // Round 4 (optimized by removing final unused rotation of v2)
    v0 = add(v0, v1);
    v1 = rotl(v1, 5);
    v1 ^= v0;
    v0 = rotl(v0, 16);
    v2 = add(v2, v3);
    v3 = rotl(v3, 8);
    v3 ^= v2;
    v0 = add(v0, v3);
    v3 = rotl(v3, 7);
    v3 ^= v0;
    v2 = add(v2, v1);
    v1 = rotl(v1, 13);
    v1 ^= v2;

    return (v1 ^ v3) >>> 0;
}
