// Copyright (C) 2020 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { KeyAgreement } from "@stablelib/keyagreement";
import { randomBytes, RandomSource } from "@stablelib/random";
import { wipe } from "@stablelib/wipe";
import { PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
    SHARED_KEY_LENGTH,
    generateKeyPairFromSeed,
    sharedKey,
    KeyPair } from "@stablelib/x25519";
import { SessionKeys, clientSessionKeysFromSharedKey, serverSessionKeysFromSharedKey } from "./x25519-session";

/** Constants for key agreement */
export const OFFER_MESSAGE_LENGTH = PUBLIC_KEY_LENGTH;
export const ACCEPT_MESSAGE_LENGTH = PUBLIC_KEY_LENGTH;
export const SAVED_STATE_LENGTH = SECRET_KEY_LENGTH;
export const SECRET_SEED_LENGTH = SECRET_KEY_LENGTH;

/**
 * X25519 key agreement using ephemeral key pairs.
 *
 * Note that unless this key agreement is combined with an authentication
 * method, such as public key signatures, it's vulnerable to man-in-the-middle
 * attacks.
 */
export class X25519Session implements KeyAgreement {
    readonly offerMessageLength = OFFER_MESSAGE_LENGTH;
    readonly acceptMessageLength = ACCEPT_MESSAGE_LENGTH;
    readonly sharedKeyLength = SHARED_KEY_LENGTH;
    readonly savedStateLength = SAVED_STATE_LENGTH;

    private _seed: Uint8Array;
    private _keyPair: KeyPair | undefined;
    private _sharedKey: Uint8Array | undefined;
    private _sessionKeys: SessionKeys | undefined;

    constructor(secretSeed?: Uint8Array, prng?: RandomSource) {
        this._seed = secretSeed || randomBytes(SECRET_KEY_LENGTH, prng);
    }

    saveState(): Uint8Array {
        return new Uint8Array(this._seed);
    }

    restoreState(savedState: Uint8Array): this {
        this._seed = new Uint8Array(savedState);
        return this;
    }

    clean(): void {
        if (this._seed) {
            wipe(this._seed);
        }
        if (this._keyPair) {
            wipe(this._keyPair.secretKey);
            wipe(this._keyPair.publicKey);
        }
        if (this._sharedKey) {
            wipe(this._sharedKey);
        }
        if (this._sessionKeys) {
            wipe(this._sessionKeys.receive);
            wipe(this._sessionKeys.send);
        }
    }

    offer(): Uint8Array {
        this._keyPair = generateKeyPairFromSeed(this._seed);
        return new Uint8Array(this._keyPair.publicKey);
    }

    accept(offerMsg: Uint8Array): Uint8Array {
        if (this._keyPair) {
            throw new Error("X25519Session: accept shouldn't be called by offering party");
        }
        if (offerMsg.length !== this.offerMessageLength) {
            throw new Error("X25519Session: incorrect offer message length");
        }
        if (this._sharedKey) {
            throw new Error("X25519Session: accept was already called");
        }
        const keyPair = generateKeyPairFromSeed(this._seed);
        this._sharedKey = sharedKey(keyPair.secretKey, offerMsg);
        this._sessionKeys = clientSessionKeysFromSharedKey(this._sharedKey, keyPair.publicKey, offerMsg);
        wipe(keyPair.secretKey);
        return keyPair.publicKey;
    }

    finish(acceptMsg: Uint8Array): this {
        if (acceptMsg.length !== this.acceptMessageLength) {
            throw new Error("X25519Session: incorrect accept message length");
        }
        if (!this._keyPair) {
            throw new Error("X25519Session: no offer state");
        }
        if (this._sharedKey) {
            throw new Error("X25519Session: finish was already called");
        }
        this._sharedKey = sharedKey(this._keyPair.secretKey, acceptMsg);
        this._sessionKeys = serverSessionKeysFromSharedKey(this._sharedKey, this._keyPair.publicKey, acceptMsg);
        return this;
    }

    getSharedKey(): Uint8Array {
        if (!this._sharedKey) {
            throw new Error("X25519Session: no shared key established");
        }
        return new Uint8Array(this._sharedKey);
    }

    getSessionKeys(): SessionKeys {
        if (!this._sessionKeys) {
            throw new Error("X25519Session: no shared key established");
        }
        return {
            receive: new Uint8Array(this._sessionKeys.receive),
            send: new Uint8Array(this._sessionKeys.send),
        };
    }
}
