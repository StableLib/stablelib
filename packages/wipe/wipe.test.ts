// Copyright (C) 2024 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { describe, expect, it } from 'vitest';
import { wipe } from "./wipe";

describe("wipe", () => {
    it("should wipe bytes", () => {
        const a = new Uint8Array([1, 2, 3, 4]);
        wipe(a);
        expect(a).toEqual(new Uint8Array(4));
    });
});
