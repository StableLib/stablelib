// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package gcm implements GCM mode for block ciphers.
 */

import { AEAD } from "@stablelib/aead";
import { BlockCipher } from "@stablelib/blockcipher";
import { CTR } from "@stablelib/ctr";
import { wipe } from "@stablelib/wipe";
import { writeUint32BE } from "@stablelib/binary";
import { equal } from "@stablelib/constant-time";

export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;

/**
 * Galois/Counter Mode AEAD
 *
 * Defined in NIST SP-800-38D.
 *
 * This implementation only supports 12-byte nonces and 16-byte tags:
 * these parameters are the most secure and most commonly used.
 */
export class GCM implements AEAD {
    readonly nonceLength = NONCE_LENGTH;
    readonly tagLength = TAG_LENGTH;

    // Subkey used for authentication.
    private _subkey: Uint8Array;

    // Cipher.
    private _cipher: BlockCipher;

    /**
     * Creates a new GCM instance with the given block cipher.
     *
     * Block size of cipher must be equal to 16.
     */
    constructor(cipher: BlockCipher) {
        if (cipher.blockSize !== 16) {
            throw new Error("GCM supports only 16-byte block cipher");
        }
        this._cipher = cipher;

        // Generate subkey by encrypting zero bytes.
        this._subkey = new Uint8Array(this._cipher.blockSize);
        // XXX: can avoid allocation here.
        this._cipher.encryptBlock(new Uint8Array(this._cipher.blockSize), this._subkey);
    }

    /**
     * Encrypts and authenticates plaintext, authenticates associated data,
     * and returns sealed ciphertext, which includes authentication tag.
     *
     * If dst is given (it must be the size of plaintext + the size of tag length)
     * the result will be put into it. Dst and plaintext must not overlap.
     */
    seal(nonce: Uint8Array, plaintext: Uint8Array, associatedData?: Uint8Array,
        dst?: Uint8Array): Uint8Array {
        if (nonce.length !== this.nonceLength) {
            throw new Error("GCM: incorrect nonce length");
        }

        const blockSize = this._cipher.blockSize;

        // Allocate space for sealed ciphertext.
        const resultLength = plaintext.length + this.tagLength;
        let result;
        if (dst) {
            if (dst.length !== resultLength) {
                throw new Error("GCM: incorrect destination length");
            }
            result = dst;
        } else {
            result = new Uint8Array(resultLength);
        }

        // Put nonce into the first part of counter.
        const counter = new Uint8Array(blockSize);
        counter.set(nonce);

        // Set the last part to 1 (because we used 0 for subkey).
        counter[counter.length - 1] = 1;

        // Generate tag mask by encrypting counter.
        const tagMask = new Uint8Array(blockSize);
        this._cipher.encryptBlock(counter, tagMask);

        // Increment counter.
        counter[counter.length - 1] = 2;

        // Encrypt plaintext in CTR mode.

        // TODO(dchest): counter is a 32-byte value, so add
        // assertion for plaintext length to prevent overflow?

        // XXX: can avoid allocation by pre-allocating CTR and using setCipher() here.
        const ctr = new CTR(this._cipher, counter);
        ctr.streamXOR(plaintext, result);
        ctr.clean();

        // Authenticate.
        this._authenticate(result.subarray(result.length - this.tagLength, result.length),
            tagMask, result.subarray(0, result.length - this.tagLength), associatedData);

        // Cleanup.
        wipe(counter);
        wipe(tagMask);

        return result;
    }

    /**
     * Authenticates sealed ciphertext (which includes authentication tag) and
     * associated data, decrypts ciphertext and returns decrypted plaintext.
     *
     * If authentication fails, it returns null.
     *
     * If dst is given (it must be of ciphertext length minus tag length),
     * the result will be put into it. Dst and plaintext must not overlap.
     */
    open(nonce: Uint8Array, sealed: Uint8Array, associatedData?: Uint8Array,
        dst?: Uint8Array): Uint8Array | null {
        if (nonce.length !== this.nonceLength) {
            throw new Error("GCM: incorrect nonce length");
        }

        // Sealed ciphertext should at least contain tag.
        if (sealed.length < this.tagLength) {
            // TODO(dchest): should we throw here instead?
            return null;
        }

        const blockSize = this._cipher.blockSize;

        // Put nonce into the first part of counter.
        const counter = new Uint8Array(blockSize);
        counter.set(nonce);

        // Set the last part to 1 (because we used 0 for subkey).
        counter[counter.length - 1] = 1;

        // Generate tag mask by encrypting counter.
        const tagMask = new Uint8Array(blockSize);
        this._cipher.encryptBlock(counter, tagMask);

        // Increment counter.
        counter[counter.length - 1] = 2;

        // Authenticate.
        const calculatedTag = new Uint8Array(this.tagLength);
        this._authenticate(calculatedTag, tagMask,
            sealed.subarray(0, sealed.length - this.tagLength), associatedData);

        // Constant-time compare tags and return null if they differ.
        if (!equal(calculatedTag,
            sealed.subarray(sealed.length - this.tagLength, sealed.length))) {
            return null;
        }

        // Allocate space for decrypted plaintext.
        const resultLength = sealed.length - this.tagLength;
        let result;
        if (dst) {
            if (dst.length !== resultLength) {
                throw new Error("GCM: incorrect destination length");
            }
            result = dst;
        } else {
            result = new Uint8Array(resultLength);
        }

        // Decrypt in CTR mode.
        // XXX: can avoid allocation by pre-allocating CTR and using setCipher() here.
        const ctr = new CTR(this._cipher, counter);
        ctr.streamXOR(sealed.subarray(0, sealed.length - this.tagLength), result);
        ctr.clean();

        // Cleanup.
        wipe(counter);
        wipe(tagMask);

        return result;
    }

    clean(): this {
        wipe(this._subkey);
        // Cleaning cipher is caller's responsibility.
        return this;
    }

    private _authenticate(tagOut: Uint8Array, tagMask: Uint8Array,
        ciphertext: Uint8Array, associatedData?: Uint8Array) {

        const blockSize = this._cipher.blockSize;

        // Authenticate associated data.
        if (associatedData) {
            for (let i = 0; i < associatedData.length; i += blockSize) {
                const slice = associatedData.subarray(i,
                    Math.min(i + blockSize, associatedData.length));
                addmul(tagOut, slice, this._subkey);
            }
        }

        // Authenticate ciphertext.
        for (let i = 0; i < ciphertext.length; i += blockSize) {
            const slice = ciphertext.subarray(i, Math.min(i + blockSize, ciphertext.length));
            addmul(tagOut, slice, this._subkey);
        }

        // Make a block of associated data and ciphertext (plaintext) bit lengths.
        // XXX: can avoid allocation here?
        const lengthsBlock = new Uint8Array(blockSize);
        if (associatedData) {
            writeBitLength(associatedData.length, lengthsBlock, 0);
        }
        writeBitLength(ciphertext.length, lengthsBlock, 8);
        addmul(tagOut, lengthsBlock, this._subkey);

        // XOR tag mask to get the final tag value.
        for (let i = 0; i < tagMask.length; i++) {
            tagOut[i] ^= tagMask[i];
        }

        wipe(lengthsBlock);
    }
}

// Writes big-endian 8-byte bit length of the given byte length
// into dst at the given offset.
function writeBitLength(byteLength: number, dst: Uint8Array, offset = 0) {
    const hi = (byteLength / 0x20000000) | 0;
    const lo = byteLength << 3;
    writeUint32BE(hi, dst, offset + 0);
    writeUint32BE(lo, dst, offset + 4);
}


/**
 * Add and multiply in GF(2^128)
 *
 * a = (a + x) * y in the finite field
 *
 * a is 16 bytes
 * y is 16 bytes
 * x is 0-16 bytes, if x.length <= 16; x is implicitly 0-padded
 *
 * Masking idea from Mike Belopuhov's implementation,
 * that credits John-Mark Gurney for the idea.
 * http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/crypto/gmac.c
 *
 * Addition with implicit padding before multiplication
 * is due to Daniel J. Bernstein's implementation in SUPERCOP.
 */
function addmul(a: Uint8Array, x: Uint8Array, y: Uint8Array) {
    // Add: a += x
    for (let i = 0; i < x.length; i++) {
        a[i] ^= x[i];
    }

    // Multiply: a *= y
    let v0 = (y[3] | y[2] << 8 | y[1] << 16 | y[0] << 24);
    let v1 = (y[7] | y[6] << 8 | y[5] << 16 | y[4] << 24);
    let v2 = (y[11] | y[10] << 8 | y[9] << 16 | y[8] << 24);
    let v3 = (y[15] | y[14] << 8 | y[13] << 16 | y[12] << 24);

    let z0 = 0, z1 = 0, z2 = 0, z3 = 0;

    for (let i = 0; i < 128; i++) {
        let mask = ~((((-(a[i >> 3] & (1 << (~i & 7)))) >>> 31) & 1) - 1);
        z0 ^= v0 & mask;
        z1 ^= v1 & mask;
        z2 ^= v2 & mask;
        z3 ^= v3 & mask;

        mask = ~((v3 & 1) - 1);
        v3 = (v2 << 31) | (v3 >>> 1);
        v2 = (v1 << 31) | (v2 >>> 1);
        v1 = (v0 << 31) | (v1 >>> 1);
        v0 = (v0 >>> 1) ^ (0xe1000000 & mask);
    }

    writeUint32BE(z0, a, 0);
    writeUint32BE(z1, a, 4);
    writeUint32BE(z2, a, 8);
    writeUint32BE(z3, a, 12);
}
