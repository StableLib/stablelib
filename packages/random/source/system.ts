// Copyright (C) 2024 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { RandomSource } from "./";

const QUOTA = 65536;

export class SystemRandomSource implements RandomSource {
    isAvailable = false;
    isInstantiated = false;

    constructor() {
        if (typeof crypto !== "undefined" && 'getRandomValues' in crypto) {
            this.isAvailable = true;
            this.isInstantiated = true;
        }
    }

    randomBytes(length: number): Uint8Array {
        if (!this.isAvailable) {
            throw new Error("System random byte generator is not available.");
        }
        const out = new Uint8Array(length);
        for (let i = 0; i < out.length; i += QUOTA) {
            crypto.getRandomValues(out.subarray(i, i + Math.min(out.length - i, QUOTA)));
        }
        return out;
    }
}
