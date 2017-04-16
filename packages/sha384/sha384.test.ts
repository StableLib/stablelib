// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { SHA384, hash } from "./sha384";
import { encode } from "@stablelib/base64";

const vectors = [
    "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"
];

// Test input is [ 0, 1, 2, ..., 255 ].
const input = new Uint8Array(256);
for (let i = 0; i < input.length; i++) {
    input[i] = i & 0xff;
}

describe("sha384.SHA384", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            let h = new SHA384();
            h.update(input.subarray(0, i));
            expect(encode(h.digest())).toBe(vectors[i]);
        }
    });

    it("should correctly update multiple times", () => {
        const h1 = new SHA384();
        h1.update(input.subarray(0, 1));
        h1.update(input.subarray(1, 120));
        h1.update(input.subarray(120, 256));
        const h2 = new SHA384();
        h2.update(input.subarray(0, 256));
        expect(encode(h1.digest())).toBe(encode(h2.digest()));
    });

    it("should return the same digest after finalizing", () => {
        let h = new SHA384();
        h.update(input);
        let d1 = h.digest();
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should throw when updating finalized instance", () => {
        let h = new SHA384();
        h.update(input);
        h.digest();
        expect(() => h.update(input)).toThrow();
    });

    it("should reset instance", () => {
        let h = new SHA384();
        h.update(input);
        let d1 = h.digest();
        h.reset();
        h.update(input);
        let d2 = h.digest();
        expect(encode(d1)).toBe(encode(d2));
    });

    it("should return 48-byte digest", () => {
        let h = new SHA384();
        h.update(input);
        expect(h.digest().length).toBe(48);
    });

});

describe("sha384.hash", () => {
    it("should produce correct hashes for test vectors", () => {
        for (let i = 0; i < input.length; i++) {
            const digest = hash(input.subarray(0, i));
            expect(encode(digest)).toBe(vectors[i]);
        }
    });
});
