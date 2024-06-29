// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { describe, expect, it } from 'vitest';
import { split, combine, combineRaw } from "./tss";
import { decode } from "@stablelib/hex";

describe("tss", () => {
    it("should split and combine", () => {
        const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
        const threshold = 3;
        const totalShares = 8;

        const shares = split(secret, threshold, totalShares);

        const haveShares = [
            shares[0],
            shares[5],
            shares[7]
        ];

        const restored = combine(haveShares);

        expect(restored).toEqual(secret);
    });

    it("should match test vectors", () => {
        // https://tools.ietf.org/html/draft-mcgrew-tss-03#section-9
        const secret = decode("7465737400");
        const threshold = 2;
        const shares = [decode("01B9FA07E185"), decode("02F5409B4511")];
        const restored = combineRaw(shares, threshold);
        expect(restored).toEqual(secret);
    });
});

// TODO(dchest): add more tests for invalid parameters, different hashes, etc.
