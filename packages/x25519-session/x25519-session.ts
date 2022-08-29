// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package x25519-session implements libsodium compatible session keys generation based on X25519 key agreement.
 */

import { BLAKE2b } from "@stablelib/blake2b";
import { Hash } from "@stablelib/hash";
import { sharedKey, KeyPair } from "@stablelib/x25519";
export { X25519Session } from "./keyagreement";

const SESSION_KEY_LENGTH = 32;

export interface SessionKeys {
    receive: Uint8Array;
    send: Uint8Array;
}

/**
 * Generates server-side session encryption keys from the shared key obtained during agreement phase.
 */
export function serverSessionKeysFromSharedKey(sharedKey: Uint8Array,
    myPublicKey: Uint8Array,
    theirPublicKey: Uint8Array,
    hash: new() => Hash = BLAKE2b): SessionKeys {
    const state = new hash();
    if (state.digestLength !== SESSION_KEY_LENGTH * 2) {
        throw new Error("X25519: incorrect digest length");
    }
    const h = state.update(sharedKey).update(theirPublicKey).update(myPublicKey).digest();

    return {
        send: h.subarray(0, SESSION_KEY_LENGTH),
        receive: h.subarray(SESSION_KEY_LENGTH),
    };
}

/**
 * Generates client-side session encryption keys from the shared key obtained during agreement phase.
 */
export function clientSessionKeysFromSharedKey(sharedKey: Uint8Array,
    myPublicKey: Uint8Array,
    theirPublicKey: Uint8Array,
    hash: new() => Hash = BLAKE2b): SessionKeys {
    const state = new hash();
    if (state.digestLength !== SESSION_KEY_LENGTH * 2) {
        throw new Error("X25519: incorrect digest length");
    }
    const h = state.update(sharedKey).update(myPublicKey).update(theirPublicKey).digest();

    return {
        receive: h.subarray(0, SESSION_KEY_LENGTH),
        send: h.subarray(SESSION_KEY_LENGTH),
    };
}

/**
 * Generates server-side session encryption keys. Uses a key pair and a peer's public key to generate the shared key.
 */
export function serverSessionKeys(myKeyPair: KeyPair, theirPublicKey: Uint8Array, hash: new() => Hash = BLAKE2b): SessionKeys {
    const sk = sharedKey(myKeyPair.secretKey, theirPublicKey);
    return serverSessionKeysFromSharedKey(sk, myKeyPair.publicKey, theirPublicKey, hash);
}

/**
 * Generates client-side session encryption keys. Uses a key pair and a peer's public key to generate the shared key.
 */
export function clientSessionKeys(myKeyPair: KeyPair, theirPublicKey: Uint8Array, hash: new() => Hash = BLAKE2b): SessionKeys {
    const sk = sharedKey(myKeyPair.secretKey, theirPublicKey);
    return clientSessionKeysFromSharedKey(sk, myKeyPair.publicKey, theirPublicKey, hash);
}
