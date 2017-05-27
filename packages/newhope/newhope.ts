// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

// Implementation ported from BoringSSL:
// https://boringssl.googlesource.com/boringssl/+/master/crypto/newhope/
// https://boringssl.googlesource.com/boringssl/+/master/ssl/test/runner/newhope/

// Copyright (c) 2016, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Reimplemented from the public domain reference implementation
// at https://github.com/tpoeppelmann/newhope.

import { RandomSource } from "@stablelib/random";
import { SHAKE128, SHA3256 } from "@stablelib/sha3";
import { SeedExpander, CustomNewHope } from "./custom";

export {
    PUBLIC_SEED_LENGTH,
    SECRET_SEED_LENGTH,
    OFFER_MESSAGE_LENGTH,
    ACCEPT_MESSAGE_LENGTH,
    SAVED_STATE_LENGTH
} from "./custom";

// Byte length of shared key.
export const SHARED_KEY_LENGTH = 32; // SHA-3 digest length

// Expands seed with SHAKE128.
class SHAKE128Expander extends SHAKE128 implements SeedExpander {
    constructor(seed: Uint8Array) {
        super();
        this.update(seed);
    }
}

/**
 * NewHope provides post-quantum Ring-LWE-based key exchange between two peers.
 *
 * One peer generates an "offer message"" by calling offer(), and sends it to
 * the other peer. The other peer accepts the offer and generates "accept
 * message" by calling accept() with the received offer message. It then send
 * the result to the first peer, which calls finish(). After completing these
 * steps, both peers call getSharedKey() to get the established shared key.
 *
 * This is a reference version, which uses SHAKE-128 and SHA-3-256. You can
 * create a custom version by requiring "lib/custom" and extending
 * CustomNewHope class.
 *
 * Reference:
 *
 * Erdem Alkim, Léo Ducas, Thomas Pöppelmann, and Peter Schwabe: Post-quantum
 * key exchange – a new hope.
 *
 * https://cryptojedi.org/papers/#newhope
 */
export class NewHope extends CustomNewHope {
    constructor(secretSeed?: Uint8Array, prng?: RandomSource) {
        super(
            SHAKE128Expander,
            SHA3256,
            secretSeed,
            prng
        );
    }
}
