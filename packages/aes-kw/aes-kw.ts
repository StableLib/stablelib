// Copyright (C) 2020 Tobias Looker
// MIT License. See LICENSE file for details.

import { AES } from "@stablelib/aes";
import { writeUint64BE } from "@stablelib/binary";
import { BlockCipher } from "@stablelib/blockcipher";
import { wipe } from "@stablelib/wipe";
import { compare } from "@stablelib/constant-time";

/**
 * An implementation of the Advance Encryption Standard Key Wrapping Algorithm (AES-KW)
 * originally designed by NIST and formalized in RFC 3394
 * @see https://tools.ietf.org/html/rfc3394
 * @see http://csrc.nist.gov/encryption/kms/key-wrap.pdf
 */
export class AESKW {
    private _inputBuffer: Uint8Array;
    private _outputBuffer: Uint8Array;
    private _cipher: BlockCipher;
    private _iv: Uint8Array;

    /**
     * Constructs AESKW instance with the given key.
     *
     * @param key: The key encryption key used to wrap and un-wrap
     */
    constructor(key: Uint8Array) {
        // Set the cipher to AES
        this._cipher = new AES(key);

        // Set the initial value to that documented in section 2.2.3.1
        // @see https://tools.ietf.org/html/rfc3394#section-2.2.3.1
        this._iv = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);

        // Initialize the input and output buffers.
        this._inputBuffer = new Uint8Array(this._cipher.blockSize);
        this._outputBuffer = new Uint8Array(this._cipher.blockSize);
    }

    /**
     * Cleans the buffers and underlying memory associated to the cipher.
     */
    clean(): this {
        wipe(this._inputBuffer);
        wipe(this._outputBuffer);
        this._cipher.clean();
        return this;
    }

    /**
     * Wraps supplied key data with the key encryption key supplied in the constructor.
     *
     * @param keyData: The key data to wrap with the key encryption key
     */
    wrapKey(keyData: Uint8Array): Uint8Array {
        // Floor divide the length of the key data to determine
        // how many 64 bit data blocks it contains.
        const N = (keyData.length - (keyData.length % 8)) / 8;

        // The keyData must be at minimum 128 bit (16 bytes) in length.
        if (N <= 1) {
            throw new Error("AESKW: key size must be at least 16 bytes");
        }

        // Set A to the initial value.
        const A = new Uint8Array(this._iv);

        // Initialize the length of the wrapped key, size always equals N+1.
        const wrappedKey = new Uint8Array(8 * (N + 1));

        // Set the plain text into the wrapped key array offset
        // by one 64 bit data block.
        wrappedKey.set(keyData, 8);

        for (let j = 0; j < 6; j++) {
            for (let i = 1; i <= N; i++) {
                this._inputBuffer.set(A);
                this._inputBuffer.set(wrappedKey.subarray(i * 8, (i + 1) * 8), 8);
                this._cipher.encryptBlock(this._inputBuffer, this._outputBuffer);
                writeUint64BE(i + j * N, A);
                xor(A, this._outputBuffer.subarray(0, 8));
                wrappedKey.set(this._outputBuffer.subarray(8, 16), i * 8);
            }
        }

        wrappedKey.set(A);
        wipe(A);
        return wrappedKey;
    }

    /**
     * Un-wraps a wrapped key using the key encryption key supplied in the
     * constructor
     * @param wrappedKey: The wrapped key to un-wrap with the key encryption key
     */
    unwrapKey(wrappedKey: Uint8Array): Uint8Array {
        // Floor divide the length of the unwrapped key to determine
        // how many 64 bit data blocks it contains, N represents the number
        // of 64 bit data blocks of the plain text which is always one less
        // than the cipher text
        const N = ((wrappedKey.length - (wrappedKey.length % 8)) / 8) - 1;

        // The keyData must be at minimum 128 bit (16 bytes) in length
        if (N <= 1) {
            throw new Error("AESKW: key size must be at least 16 bytes");
        }

        // Set A to the first 64 bit data block of the wrapped key.
        const A = new Uint8Array(wrappedKey.subarray(0, 8));

        // Allocate temporary array.
        const tmp = new Uint8Array(8);

        // Initialize the length of the key data, size always equals N.
        const keyData = new Uint8Array(8 * N);
        const encryptedKeyData = new Uint8Array(wrappedKey);

        for (let j = 5; j >= 0; j--) {
            for (let i = N; i >= 1; i--) {
                writeUint64BE(i + j * N, tmp);
                xor(A, tmp);
                this._inputBuffer.set(A);
                this._inputBuffer.set(encryptedKeyData.subarray((i) * 8, (i + 1) * 8), 8);
                this._cipher.decryptBlock(this._inputBuffer, this._outputBuffer);
                A.set(this._outputBuffer.subarray(0, 8));
                encryptedKeyData.set(this._outputBuffer.subarray(8, 16), i * 8);
            }
        }

        // Integrity check, the A component of the un-wrapped key buffer should
        // equal the default initial value.
        if (compare(A, this._iv) == 0) {
            throw new Error("AESKW: integrity check failed");
        }

        keyData.set(encryptedKeyData.subarray(8));
        wipe(encryptedKeyData);
        wipe(A);
        wipe(tmp);
        return keyData;
    }
}

/**
 * Xors b into a.
 */
function xor(a: Uint8Array, b: Uint8Array) {
    for (let i = 0; i < b.length; i++) {
        a[i] ^= b[i];
    }
}
