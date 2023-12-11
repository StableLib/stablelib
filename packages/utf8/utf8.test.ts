// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import * as hex from "@stablelib/hex";
import { encode, decode } from "./utf8";

describe("utf8", () => {
    it("should encode and decode strings", () => {
        const tests = [
            "abcdef",
            "☺☻☹",
            "абвгдеёжз",
            "abcгдеjzy123",
            "こんにちは世界",
            "test 测试 тест",
            "𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡",
            "❤️"
        ];
        const encoded = tests.map(encode);
        const decoded = encoded.map(decode);
        expect(decoded).toEqual(tests);
    });

    it("should not decode malformed bytes", () => {
        // Source: https://hsivonen.fi/broken-utf-8/test.html
        const tests = [
            // Non-shortest forms for lowest single-byte (U+0000)
            "C0 80",
            "E0 80 80",
            "F0 80 80 80",
            "F8 80 80 80 80",
            "FC 80 80 80 80 80",
            // Non-shortest forms for highest single-byte (U+007F)
            "C1 BF",
            "E0 81 BF",
            "F0 80 81 BF",
            "F8 80 80 81 BF",
            "FC 80 80 80 81 BF",
            // Non-shortest forms for lowest two-byte (U+0080)
            "E0 82 80",
            "F0 80 82 80",
            "F8 80 80 82 80",
            "FC 80 80 80 82 80",
            // Non-shortest forms for highest two-byte (U+07FF)
            "E0 9F BF",
            "F0 80 9F BF",
            "F8 80 80 9F BF",
            "FC 80 80 80 9F BF",
            // Non-shortest forms for lowest three-byte (U+0800)
            "F0 80 A0 80",
            "F8 80 80 A0 80",
            "FC 80 80 80 A0 80",
            // Non-shortest forms for highest three-byte (U+FFFF)
            "F0 8F BF BF",
            "F8 80 8F BF BF",
            "FC 80 80 8F BF BF",
            // Non-shortest forms for lowest four-byte (U+10000)
            "F8 80 90 80 80",
            "FC 80 80 90 80 80",
            // Non-shortest forms for last Unicode (U+10FFFF)
            "F8 84 8F BF BF",
            "FC 80 84 8F BF BF",
            // Out of range
            "F4 90 80 80",
            "FB BF BF BF BF",
            "FD BF BF BF BF BF",
            "ED A0 80",
            "ED BF BF",
            "ED A0 BD ED B2 A9",
            // Out of range and non-shortest
            "F8 84 90 80 80",
            "FC 80 84 90 80 80",
            "F0 8D A0 80",
            "F0 8D BF BF",
            "F0 8D A0 BD F0 8D B2 A9",
            // Lone trails
            "80",
            "80 80",
            "80 80 80",
            "80 80 80 80",
            "80 80 80 80 80",
            "80 80 80 80 80 80",
            "80 80 80 80 80 80 80",
            "C2 B6 80",
            "E2 98 83 80",
            "F0 9F 92 A9 80",
            "FB BF BF BF BF 80",
            "FD BF BF BF BF BF 80",
            // Truncated sequences
            "C2",
            "E2",
            "E2 98",
            "F0",
            "F0 9F",
            "F0 9F 92",
            // Leftovers
            "FE",
            "FE 80",
            "FF",
            "FF 80"
        ];
        tests.forEach((s, i) => {
            const b = hex.decode(s.replace(/ /g, ""));
            expect(() => {
                const x = decode(b);
                // The following will only run in case of unsuccessful test:
                console.log(i, "should not have decoded", s, "to", x);
            }).toThrowError(/invalid/);
        });
    });

    it("should decode a huge string", () => {
        let s = "";
        for (let i = 0; i < 1024 * 1024; i++) {
            s += "это test";
        }
        const enc = encode(s);
        const dec = decode(enc);
        expect(dec).toEqual(s);
    });
});
