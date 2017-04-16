// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { Hash } from "@stablelib/hash";
import { SHA256 } from "@stablelib/sha256";
import { randomBytes, RandomSource } from "@stablelib/random";
import { add, mul, div } from "@stablelib/gf256";
import { wipe } from "@stablelib/wipe";
import { equal } from "@stablelib/constant-time";

export const HASH_ID_NULL = 0;
export const HASH_ID_SHA1 = 1;
export const HASH_ID_SHA256 = 2;
export const HASH_ID_VENDOR_MIN = 128;

export const IDENTIFIER_LENGTH = 16;
export const MAX_SECRET_LENGTH = 65534;
export const MAX_SHARES = 255;

/**
 * Threshold Secret Sharing.
 *
 * TSS provides a way to split a byte array into N byte arrays,
 * any M ("threshold") of which can be combined to restore the
 * original byte array. It is typically used to split secret
 * cryptographic keys between people to provide shared access
 * to data.
 *
 * This module implements IETF Internet-Draft
 * https://tools.ietf.org/html/draft-mcgrew-tss-03
 */

/**
 * Split secret into the given number of raw shares, threshold number of
 * which can be used with combineRaw() to recover it.
 *
 * It is recommended to use split(), which produces robust shares with
 * identifier and hash of secret.
 */
export function splitRaw(secret: Uint8Array, threshold: number, totalShares: number,
    prng?: RandomSource): Uint8Array[] {

    // Validate arguments.
    if (threshold < 1 || threshold > MAX_SHARES) {
        throw new Error(`tss: threshold must be between 1 and ${MAX_SHARES} inclusive`);
    }

    if (totalShares < threshold || totalShares > MAX_SHARES) {
        throw new Error(`tss: number of shares must be between threshold and ${MAX_SHARES} inclusive`);
    }

    if (secret.length > MAX_SECRET_LENGTH) {
        throw new Error(`tss: secret is too long, maximum size is ${MAX_SECRET_LENGTH} bytes`);
    }

    const shareLength = 1 + secret.length;
    let shares: Uint8Array[] = [];

    // Get random bytes.
    // Strictly speaking, since the first byte will be overwritten,
    // we need to generate one byte fewer, however to avoid allocations
    // and copying, we just request the whole array of random bytes.
    const a = randomBytes(threshold, prng);

    for (let x = 1; x <= totalShares; x++) {
        const share = new Uint8Array(shareLength);
        share[0] = x;
        for (let i = 0; i < secret.length; i++) {
            a[0] = secret[i];
            share[i + 1] = f(x, a);
        }
        shares.push(share);
    }
    wipe(a);

    return shares;
}

/**
 * Split secret into the given number of robust shares, threshold number of which
 * can be used with combine() to recover it.
 *
 * Identifier is an arbitrary 16 bytes used to describe and identify shares,
 * which will be appended to shares and can be read with readIdentifier().
 *
 * The default hash function used to verify correctness of restored secret
 * is SHA-256. To use another function, pass its constructor and identifier.
 * Pass null as hash function to avoid hashing secret.
 */
export function split(secret: Uint8Array, threshold: number, totalShares: number,
    identifier = new Uint8Array(IDENTIFIER_LENGTH),
    hash: (new () => Hash) | null = SHA256,
    hashId = hash ? HASH_ID_SHA256 : HASH_ID_NULL,
    prng?: RandomSource): Uint8Array[] {

    // Validate arguments.
    if (identifier.length !== IDENTIFIER_LENGTH) {
        throw new Error(`tss: identifier must be ${IDENTIFIER_LENGTH} bytes`);
    }

    if (hashId > 255) {
        throw new Error("tss: incorrect hash identifier");
    }

    if (hash && hashId === HASH_ID_NULL) {
        throw new Error("tss: non-null hash with NULL hash identifier");
    }

    let robustSecret = secret;
    if (hash) {
        // robustSecret = secret || hash(secret)
        const h = new hash();
        robustSecret = new Uint8Array(secret.length + h.digestLength);
        robustSecret.set(secret);
        h.update(secret);
        h.finish(robustSecret.subarray(secret.length));
        h.clean();
    }

    const shares = splitRaw(robustSecret, threshold, totalShares, prng);

    const shareLength = shares[0].length;
    const robustShareLength = IDENTIFIER_LENGTH + 1 + 1 + 2 + shareLength;
    for (let i = 0; i < shares.length; i++) {
        let rs = new Uint8Array(robustShareLength);
        rs.set(identifier);
        rs[16] = hashId;
        rs[17] = threshold;
        rs[18] = (shareLength >>> 8) & 0xff;
        rs[19] = (shareLength >>> 0) & 0xff;
        rs.set(shares[i], 20);
        wipe(shares[i]);
        shares[i] = rs;
    }

    return shares;
}

/**
 * Combine raw shares to restore the original secret.
 *
 * The number of shares must be equal to or greater than threshold,
 * which must also be passed as an argument.
 */
export function combineRaw(shares: Uint8Array[], threshold: number = shares.length): Uint8Array {
    if (shares.length === 0) {
        throw new Error("tss: no shares given");
    }

    // Verify share length.
    const shareLength = shares[0].length;

    for (let i = 0; i < threshold; i++) {
        if (shares[i].length !== shareLength) {
            throw new Error("tss: different length of shares");
        }
    }

    // Calculate U.
    let u = new Uint8Array(threshold);
    for (let i = 0; i < threshold; i++) {
        u[i] = shares[i][0];
        // Check that share index is not zero.
        if (u[i] === 0) {
            throw new Error("tss: malformed share index");
        }
        // Check that there are no duplicates.
        for (let j = 0; j < i; j++) {
            if (u[i] === u[j]) {
                throw new Error("tss: repeated share index");
            }
        }
    }

    // Restore secret.
    const secret = new Uint8Array(shareLength - 1);
    const v = new Uint8Array(threshold);
    for (let b = 1; b < shareLength; b++) {
        for (let i = 0; i < threshold; i++) {
            v[i] = shares[i][b];
        }
        secret[b - 1] = I(u, v);
    }

    wipe(v);
    wipe(u);

    return secret;
}

/**
 * Returns copy of identifier from robust share.
 */
export function readIdentifier(share: Uint8Array): Uint8Array {
    if (share.length < 20) {
        throw new Error("tss: share doesn't have identifier, not robust?");
    }
    return new Uint8Array(share.subarray(0, 16));
}

/**
 * Returns threshold specified when creating this robust share.
 */
export function readThreshold(share: Uint8Array): number {
    if (share.length < 20) {
        throw new Error("tss: share is not robust?");
    }
    return share[17];
}

/**
 * Combines robust shares to restore the original secret.
 * The number of shares must be equal to or greater than threshold.
 *
 * If a custom hash was used when creating shares, it must be
 * passed as an argument along with the hash identifier.
 */
export function combine(shares: Uint8Array[], customHash?: new () => Hash,
    customHashId?: number): Uint8Array {
    if (shares.length === 0) {
        throw new Error("tss: no shares given");
    }

    // Verify that identifier, threshold and share length are the same,
    // and that shares are the same length.
    const metadata = shares[0].subarray(0, 20);
    const length = shares[0].length;
    for (let i = 1; i < shares.length; i++) {
        if (!equal(shares[i].subarray(0, 20), metadata)) {
            throw new Error("tss: different metadata");
        }
        if (shares[i].length !== length) {
            throw new Error("tss: different share length");
        }
    }

    // Verify share length.
    const shareLength = (((metadata[18] & 0xff) << 8) | (metadata[19] & 0xff)) >>> 0;
    if (shareLength !== shares[0].length - 20) {
        throw new Error("tss: incorrect share length");
    }

    // Verify that we have threshold or more number of shares.
    const threshold = metadata[17];
    if (shares.length < threshold) {
        throw new Error("tss: number of shares is less than threshold");
    }

    // Convert shares to raw share data.
    const rawShares: Uint8Array[] = [];
    for (let i = 0; i < threshold; i++) {
        rawShares.push(shares[i].subarray(20));
    }

    // Restore raw secret.
    const secret = combineRaw(rawShares, threshold);

    // Check restored secret hash.
    const hashId = metadata[16];

    if (hashId === HASH_ID_NULL) {
        return secret;
    }

    if (hashId === HASH_ID_SHA1 && customHashId !== HASH_ID_SHA1) {
        throw new Error("tss: SHA1 is not supported unless provided as a custom hash");
    }

    let h: Hash;
    if (hashId === HASH_ID_SHA256) {
        h = new SHA256();
    } else {
        if (!customHash) {
            throw new Error("tss: requires custom hash");
        }
        if (customHashId && hashId !== customHashId) {
            throw new Error("tss: hash identifier doesn't match the provided");
        }
        h = new customHash();
    }
    if (secret.length < h.digestLength) {
        throw new Error("tss: malformed secret, has fewer bytes than hash digest");
    }
    h.update(secret.subarray(0, secret.length - h.digestLength));
    const calcDigest = h.digest();
    h.clean();

    const haveDigest = secret.subarray(secret.length - h.digestLength);

    if (!equal(haveDigest, calcDigest)) {
        throw new Error("tss: failed to restore secret: hash doesn't match");
    }

    return secret.subarray(0, secret.length - h.digestLength);
}

function f(x: number, a: Uint8Array): number {
    let sum = 0;
    let xi = 1;
    for (let i = 0; i < a.length; i++) {
        sum = add(sum, mul(a[i], xi));
        xi = mul(xi, x);
    }
    return sum;
}

function Li(u: Uint8Array, i: number): number {
    let prod = 1;
    for (let j = 0; j < u.length; j++) {
        if (j !== i) {
            prod = mul(prod, div(u[j], add(u[j], u[i])));
        }
    }
    return prod;
}

function I(u: Uint8Array, v: Uint8Array): number {
    let sum = 0;
    for (let i = 0; i < v.length; i++) {
        sum = add(sum, mul(Li(u, i), v[i]));
    }
    return sum;
}
