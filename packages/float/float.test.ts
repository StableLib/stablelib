// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { isNegativeZero, fround } from "./float";

describe("isNegativeZero", () => {
    it("should return true for -0", () => {
        expect(isNegativeZero(-0)).toBe(true);
    });
    it("should return false for +0", () => {
        expect(isNegativeZero(0)).toBe(false);
    });
    it("should return false for 1", () => {
        expect(isNegativeZero(1)).toBe(false);
    });
    it("should return false for -1", () => {
        expect(isNegativeZero(-1)).toBe(false);
    });
    it("should return false for -Infinity", () => {
        expect(isNegativeZero(-Infinity)).toBe(false);
    });
    it("should return false for +Infinity", () => {
        expect(isNegativeZero(+Infinity)).toBe(false);
    });
    it("should return false for NaN", () => {
        expect(isNegativeZero(NaN)).toBe(false);
    });
});

describe("fround", () => {
    it("should return correct values for test vectors", () => {
        const vectors = [
            [0, 0],
            [1, 1],
            [1.337, 1.3370000123977661],
            [1.5, 1.5],
            [-1, -1],
            [-1.337, -1.3370000123977661],
            [Infinity, Infinity],
            [-Infinity, -Infinity],
            [-1.337, -1.3370000123977661]
        ];
        vectors.forEach(([arg, result]) => {
            expect(fround(arg)).toBe(result);
        });
        expect(isNaN(fround(NaN))).toBe(true);
        expect(isNegativeZero(fround(-0))).toBe(true);
    });
});
