// Copyright (C) 2019 Kyle Den Hartog
// MIT License. See LICENSE file for details.

import { AEAD } from "@stablelib/aead";
import { hchacha } from "@stablelib/xchacha20";
import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";
import { wipe } from "@stablelib/wipe";


export const KEY_LENGTH = 32;
export const NONCE_LENGTH = 24;
export const TAG_LENGTH = 16;

/**
 * XChaCha20-Poly1305 Authenticated Encryption with Associated Data.
 *
 * Defined in draft-irtf-cfrg-xchacha.
 * see https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01
 */
export class XChaCha20Poly1305 implements AEAD {
  readonly nonceLength = NONCE_LENGTH;
  readonly tagLength = TAG_LENGTH;

  private _key: Uint8Array;

  /**
   * Creates a new instance with the given 32-byte key.
   */
  constructor(key: Uint8Array) {
    if (key.length !== KEY_LENGTH) {
      throw new Error("ChaCha20Poly1305 needs 32-byte key");
    }
    // Copy key.
    this._key = new Uint8Array(key);
  }

  /**
   * Encrypts and authenticates plaintext, authenticates associated data,
   * and returns sealed ciphertext, which includes authentication tag.
   *
   * draft-irtf-cfrg-xchacha defines a 24 byte nonce (192 bits) which
   * then uses the first 16 bytes of the nonce and the secret key with
   * Hchacha to generate an initial subkey. The last 8 bytes of the nonce
   * are then prefixed with 4 null bytes and then provided with the subkey
   * to the chacha20poly1305 implementation.
   *
   * If dst is given (it must be the size of plaintext + the size of tag
   * length) the result will be put into it. Dst and plaintext must not
   * overlap.
   */
  seal(
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData?: Uint8Array,
    dst?: Uint8Array
  ): Uint8Array {
    if (nonce.length !== 24) {
      throw new Error("XChaCha20Poly1305: incorrect nonce length");
    }
    // Use HSalsa one-way function to transform first 16 bytes of
    // 24-byte extended nonce and key into a new key for Salsa
    // stream -- "subkey".
    const subKey = hchacha(this._key, nonce.subarray(0, 16), new Uint8Array(32));


    // Use last 8 bytes of 24-byte extended nonce as an actual nonce prefixed by 4 NUL bytes,
    // and a subkey derived in the previous step as key to encrypt.
    const modifiedNonce = new Uint8Array(12);
    modifiedNonce.set(nonce.subarray(16), 4);

    const resultLength = plaintext.length + this.tagLength;
    let result;
    if (dst) {
      if (dst.length !== resultLength) {
        throw new Error(
          "XChaCha20Poly1305: incorrect destination length"
        );
      }
      result = dst;
    } else {
      result = new Uint8Array(resultLength);
    }

    const chachapoly1305 = new ChaCha20Poly1305(subKey);

    chachapoly1305.seal(modifiedNonce, plaintext, associatedData, result);

    return result;
  }

  /**
   * Authenticates sealed ciphertext (which includes authentication tag) and
   * associated data, decrypts ciphertext and returns decrypted plaintext.
   *
   * draft-irtf-cfrg-xchacha-01 defines a 24 byte nonce (192 bits) which
   * then uses the first 16 bytes of the nonce and the secret key with
   * Hchacha to generate an initial subkey. The last 8 bytes of the nonce
   * are then prefixed with 4 null bytes and then provided with the subkey
   * to the chacha20poly1305 implementation.
   *
   * If dst is given (it must be the size of plaintext + the size of tag
   * length) the result will be put into it. Dst and plaintext must not
   * overlap.
   */
  open(
    nonce: Uint8Array,
    sealed: Uint8Array,
    associatedData?: Uint8Array,
    dst?: Uint8Array
  ): Uint8Array | null {
    if (nonce.length !== 24) {
      throw new Error("XChaCha20Poly1305: incorrect nonce length");
    }

    // Sealed ciphertext should at least contain tag.
    if (sealed.length < this.tagLength) {
      // TODO(dchest): should we throw here instead?
      return null;
    }

    /**
    * Generate subKey by using HChaCha20 function as defined
    * in section 2 step 1 of draft-irtf-cfrg-xchacha-03
    */
    const subKey = hchacha(
      this._key,
      nonce.subarray(0, 16),
      new Uint8Array(32)
    );

    /**
    * Generate Nonce as defined - remaining 8 bytes of the nonce prefixed with
    * 4 NUL bytes
    */
    const modifiedNonce = new Uint8Array(12);
    modifiedNonce.set(nonce.subarray(16), 4);

    // Decrypt.
    const chachaPoly1305 = new ChaCha20Poly1305(subKey);

    // Allocate space for decrypted plaintext.
    const resultLength = sealed.length - this.tagLength;
    let result;
    if (dst) {
      if (dst.length !== resultLength) {
        throw new Error("XChaCha20Poly1305: incorrect destination length");
      }
      result = dst;
    } else {
      result = new Uint8Array(resultLength);
    }

    /**
     * decrypt by calling into chacha20poly1305 as is described should be done
     * in draft-
     */
    chachaPoly1305.open(modifiedNonce, sealed, associatedData, result);

    // Cleanup.
    wipe(modifiedNonce);

    return result;
  }

  clean(): this {
    wipe(this._key);
    return this;
  }
}
