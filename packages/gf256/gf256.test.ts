// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { describe, expect, it } from 'vitest';
import { add, sub, mul, div } from "./gf256";


describe("add/sub", () => {
    it("should add/subtract", () => {
        for (let i = 0; i < 256; i++) {
            for (let j = 0; j < 256; j++) {
                expect(`${i} + ${j} = ${add(i, j)}`).toBe(`${i} + ${j} = ${i ^ j}`);
                expect(`${i} - ${j} = ${sub(i, j)}`).toBe(`${i} - ${j} = ${i ^ j}`);
            }
        }
    });
});

function slowMul(x: number, y: number): number {
    let z = 0;
    let c = 0;
    for (let i = 0; i < 8; i++) {
        if ((y & 1) === 1) {
            z ^= x;
        }
        c = x & 0x80;
        x = x << 1 & 0xff;
        y = y >>> 1 & 0xff;
        if (c === 0x80) {
            x ^= 0x1b;
        }
    }
    return z;
}

describe("mul", () => {
    it("should multiply test vector", () => {
        expect(mul(90, 21)).toBe(254);
    });

    it("should multiply", () => {
        for (let i = 0; i < 256; i++) {
            for (let j = 0; j < 256; j++) {
                expect(`${i} * ${j} = ${mul(i, j)}`).toBe(`${i} * ${j} = ${slowMul(i, j)}`);
            }
        }
    });
});

describe("div", () => {
    it("should divide", () => {
        for (let i = 0; i < 256; i++) {
            for (let j = 0; j < 256; j++) {
                const m = mul(i, j);
                if (i > 0) {
                    expect(div(m, i)).toBe(j);
                }
                if (j > 0) {
                    expect(div(m, j)).toBe(i);
                }
            }
        }
    });
});

// TODO(dchest): tests for inv.
