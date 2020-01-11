// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package pbkdf2 implements PBKDF2 password-based key derivation function.
 */

import { SerializableHash } from "@stablelib/hash";
import { HMAC } from "@stablelib/hmac";
import { writeUint32BE } from "@stablelib/binary";
import { wipe } from "@stablelib/wipe";

/**
 * Derives key from password with PBKDF2 algorithm using
 * the given hash function in HMAC construction.
 */
export function deriveKey(hash: new () => SerializableHash, password: Uint8Array,
    salt: Uint8Array, iterations: number, length: number): Uint8Array {
    const prf = new HMAC(hash, password);
    const dlen = prf.digestLength;
    const ctr = new Uint8Array(4);
    const t = new Uint8Array(dlen);
    const u = new Uint8Array(dlen);
    const dk = new Uint8Array(length);

    const saltedState = prf.update(salt).saveState();

    for (let i = 0; i * dlen < length; i++) {
        writeUint32BE(i + 1, ctr);
        prf.restoreState(saltedState).update(ctr).finish(u);
        for (let j = 0; j < dlen; j++) {
            t[j] = u[j];
        }
        for (let j = 2; j <= iterations; j++) {
            prf.reset().update(u).finish(u);
            for (let k = 0; k < dlen; k++) {
                t[k] ^= u[k];
            }
        }
        for (let j = 0; j < dlen && i * dlen + j < length; j++) {
            dk[i * dlen + j] = t[j];
        }
    }

    wipe(t);
    wipe(u);
    wipe(ctr);
    prf.cleanSavedState(saltedState);
    prf.clean();

    return dk;
}
