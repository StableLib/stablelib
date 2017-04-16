// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

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
            "𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡"
        ];
        const encoded = tests.map(encode);
        const decoded = encoded.map(decode);
        expect(decoded).toEqual(tests);
    });
});
