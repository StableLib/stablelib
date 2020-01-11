// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package hmac-drbg implements NIST's HMAC-based digital random byte generator.
 */

import { defaultRandomSource, RandomSource } from "@stablelib/random";
import { HMAC } from "@stablelib/hmac";
import { Hash } from "@stablelib/hash";
import { SHA256 } from "@stablelib/sha256";
import { wipe } from "@stablelib/wipe";

const RESEED_INTERVAL = 255;
const MAX_BYTES_PER_REQUEST = 65536;

/**
 * HMAC_DRBG from NIST SP800 90A.
 * http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
 */
export class HMACDRBG implements RandomSource {
    private _K: Uint8Array;
    private _V: Uint8Array;
    private _reseedCounter: number;
    private _byteZero = new Uint8Array([0x00]);
    private _byteOne = new Uint8Array([0x01]);
    private _digestLength: number;

    isAvailable = false;
    isInstantiated = false;

    constructor(
        private _entropySource: RandomSource = defaultRandomSource,
        private _hash: new () => Hash = SHA256,
        private _personalization = new Uint8Array(0),
        private _reseedInterval = RESEED_INTERVAL // set to 0 to disable reseeding (not recommended)
    ) {
        this.isAvailable = this._entropySource.isAvailable;
    }

    private _instantiate() {
        if (!this._entropySource.isAvailable) {
            throw new Error("HMACDRBG: entropy source is not available");
        }

        let h = new this._hash(); // to learn digest length
        this._digestLength = h.digestLength;

        this._K = new Uint8Array(h.digestLength);
        this._V = new Uint8Array(h.digestLength);
        for (let i = 0; i < this._V.length; i++) {
            this._V[i] = 0x01;
        }

        // Initial seed is (entropy || nonce || personalization).
        //
        // Nonce is "a value with at least (1/2 security_strength) bits
        // of entropy", ... "may be acquired from the same source and at
        // the same time as the entropy input". (8.6.7, p. 22)
        const n = h.digestLength + h.digestLength / 2;
        const initialSeed = new Uint8Array(n + this._personalization.length);

        // Acquire initial entropy and nonce and copy them into initial seed.
        const entropy = this._entropySource.randomBytes(n);
        initialSeed.set(entropy);

        // Copy personalization string.
        initialSeed.set(this._personalization, n);

        this._update(initialSeed);
        this._reseedCounter = 1;

        // Cleanup.
        wipe(entropy);
        wipe(initialSeed);

        this.isInstantiated = true;
    }

    private _reseed() {
        const entropy = this._entropySource.randomBytes(this._digestLength);
        this._update(entropy);
        this._reseedCounter = 1;

        // Cleanup.
        wipe(entropy);
    }

    private _update(data?: Uint8Array) {
        // K = HMAC (K, V || 0x00 || provided_data)
        let h = new HMAC(this._hash, this._K);
        h.update(this._V);
        h.update(this._byteZero);
        if (data && data.length > 0) {
            h.update(data);
        }
        h.finish(this._K).clean();

        // V = HMAC (K, V)
        h = new HMAC(this._hash, this._K);
        h.update(this._V);
        h.finish(this._V);

        // If (provided_data = Null), then return K and V.
        if (!data || data.length === 0) {
            h.clean();
            return;
        }

        // K = HMAC (K, V || 0x01 || provided_data)
        h.reset();
        h.update(this._V);
        h.update(this._byteOne);
        h.update(data);
        h.finish(this._K).clean();

        // V = HMAC (K, V)
        h = new HMAC(this._hash, this._K);
        h.update(this._V);
        h.finish(this._V).clean();
    }

    private _generate(out: Uint8Array): void {
        if (this._reseedInterval > 0 && this._reseedCounter > this._reseedInterval) {
            this._reseed();
        }
        let h = new HMAC(this._hash, this._K);
        for (let i = 0; i < out.length; i += h.digestLength) {
            h.update(this._V);
            h.finish(this._V);
            h.reset();
            for (let j = i; j < i + h.digestLength && j < out.length; j++) {
                out[j] = this._V[j - i];
            }
        }
        h.clean();
        this._update();
        this._reseedCounter++;
    }

    randomBytes(length: number): Uint8Array {
        if (!this.isInstantiated) {
            this._instantiate();
        }
        const out = new Uint8Array(length);
        for (let i = 0; i < out.length; i += MAX_BYTES_PER_REQUEST) {
            this._generate(out.subarray(i, i + Math.min(out.length - i, MAX_BYTES_PER_REQUEST)));
        }
        return out;
    }
}
