// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { HMACDRBG } from "./hmac-drbg";
import { RandomSource } from "@stablelib/random/source";
import { benchmark, report } from "@stablelib/benchmark";

class XKCDSource implements RandomSource {
    isAvailable = true;

    randomBytes(length: number): Uint8Array {
        const out = new Uint8Array(length);

        for (let i = 0; i < length; i++) {
            out[i] = 4; // chosen by fair dice roll.
                        // guaranteed to be random
        }
        return out;
    }
}

const drbg = new HMACDRBG(new XKCDSource());

report("HMAC_DRBG", benchmark(() => drbg.randomBytes(1024), 1024));
