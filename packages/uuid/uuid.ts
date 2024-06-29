// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package uuid implements UUID generator.
 */

import type { RandomSource } from "@stablelib/random";
import { randomBytes } from "@stablelib/random";
import { encode } from "@stablelib/hex";
import { wipe } from "@stablelib/wipe";

/**
 * Returns a new universally unique identifier.
 *
 * UUID v4, generated using a cryptographically
 * strong random number generator.
 */
export function uuid(prng?: RandomSource): string {
    const b = randomBytes(16, prng);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const x = encode(b, true);
    wipe(b);
    return x.substring(0, 8) + "-" +
        x.substring(8, 12) + "-" +
        x.substring(12, 16) + "-" +
        x.substring(16, 20) + "-" +
        x.substring(20, 32);
}
