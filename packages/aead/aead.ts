// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Authenticated Encryption with Associated Data.
 */
export interface AEAD {
    /**
     * Byte length of nonce that is used with this AEAD.
     */
    nonceLength: number;

    /**
     * Byte length of authentication tag in the sealed ciphertext.
     * Result of seal() will be longer than plaintext for this number of bytes.
     */
    tagLength: number;

    /**
     * Encrypts and authenticates plaintext, authenticates associated data,
     * and returns ciphertext, which includes authentication tag.
     *
     * If dst is given (it must be the size of plaintext + the size of tag length)
     * the result will be put into it. Dst and plaintext must not overlap.
     */
    seal(nonce: Uint8Array, plaintext: Uint8Array, associatedData?: Uint8Array,
        dst?: Uint8Array): Uint8Array;

    /**
     * Authenticates ciphertext (which includes authentication tag) and
     * associated data, decrypts ciphertext and returns decrypted plaintext.
     *
     * If authentication fails, it returns null.
     *
     * If dst is given (it must be of ciphertext length minus tag length),
     * the result will be put into it. Dst and plaintext must not overlap.
     */
    open(nonce: Uint8Array, ciphertext: Uint8Array, associatedData?: Uint8Array,
        dst?: Uint8Array): Uint8Array | null;

    /**
     * Wipes state from memory.
     * This doesn't wipe the underlying block cipher state.
     */
    clean(): this;
}
