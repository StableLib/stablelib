// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import * as hex from "@stablelib/hex";
import { concat } from "@stablelib/bytes";
import {
    encode, decode, Simple, Tagged, TaggedEncoder, TaggedDecoder,
    DEFAULT_TAGGED_ENCODERS, DEFAULT_TAGGED_DECODERS
} from "./cbor";

// Test vectors from RFC 7049: Appendix A.  Examples.
const encoderTestVectors = [
    0, "00",
    1, "01",
    10, "0a",
    23, "17",
    24, "1818",
    25, "1819",
    100, "1864",
    1000, "1903e8",
    1000000, "1a000f4240",
    1000000000000, "1b000000e8d4a51000",
    // 18446744073709551615, "1bffffffffffffffff", // 64-bit integer, cannot be represented in JS
    // 18446744073709551616, "c249010000000000000000",  // big integer, not supported yet
    // -18446744073709551616, "3bffffffffffffffff",  // 64-bit integer, cannot be represented in JS
    // -18446744073709551617, "c349010000000000000000",  // big integer, not supported yet
    -1, "20",
    -10, "29",
    -100, "3863",
    -1000, "3903e7",
    // 0.0, "f90000", // 0.0 encoded as integer 0
    -0.0, "f98000",
    // 1.0, "f93c00", // integer
    1.1, "fb3ff199999999999a",
    // 1.5, "f93e00", // not supporting float16 for encoding
    // 65504.0, "f97bff",
    // 100000.0, "fa47c35000", // integer
    3.4028234663852886e+38, "fa7f7fffff",
    1.0e+300, "fb7e37e43c8800759c",
    // 5.960464477539063e-8, "f90001", // not supporting float16 for encoding
    // 0.00006103515625, "f90400", // not supporting float16 for encoding
    // -4.0, "f9c400", // not supporting float16 for encoding
    -4.1, "fbc010666666666666",
    Infinity, "f97c00",
    NaN, "f97e00",
    -Infinity, "f9fc00",
    false, "f4",
    true, "f5",
    null, "f6",
    undefined, "f7",
    new Simple(16), "f0",
    new Simple(24), "f818",
    new Simple(255), "f8ff",
    new Date("2013-03-21T20:04:00Z"), "c074323031332d30332d32315432303a30343a30305a",
    new Tagged(1, 1363896240), "c11a514b67b0", // epoch date
    new Tagged(1, 1363896240.5), "c1fb41d452d9ec200000", // epoch date
    new Tagged(23, new Uint8Array([1, 2, 3, 4])), "d74401020304",
    new Tagged(24, new Uint8Array([0x64, 0x49, 0x45, 0x54, 0x46])), "d818456449455446",
    new Tagged(32, "http://www.example.com"), "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
    new Uint8Array(0), "40",
    new Uint8Array([1, 2, 3, 4]), "4401020304",
    "", "60",
    "a", "6161",
    "IETF", "6449455446",
    "\"\\", "62225c",
    "\u00fc", "62c3bc",
    "\u6c34", "63e6b0b4",
    "\ud800\udd51", "64f0908591",
    [], "80",
    [1, 2, 3], "83010203",
    [1, [2, 3], [4, 5]], "8301820203820405",
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25], "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
    {}, "a0",
    // { 1: 2, 3: 4 }, "a201020304", // in JS keys are always strings
    { "a": 1, "b": [2, 3] }, "a26161016162820203",
    ["a", { "b": "c" }], "826161a161626163",
    { "a": "A", "b": "B", "c": "C", "d": "D", "e": "E" }, "a56161614161626142616361436164614461656145",
    /^a[bc]+$/gi, "d8236c2f5e615b62635d2b242f6769"
];

const decoderTestVectors = [
    0, "00",
    1, "01",
    10, "0a",
    23, "17",
    24, "1818",
    25, "1819",
    100, "1864",
    1000, "1903e8",
    1000000, "1a000f4240",
    1000000000000, "1b000000e8d4a51000",
    -1, "20",
    -10, "29",
    -100, "3863",
    -1000, "3903e7",
    0.0, "f90000",
    -0.0, "f98000",
    -0.0, "fb8000000000000000",
    1.0, "f93c00",
    1.1, "fb3ff199999999999a",
    1.5, "f93e00",
    65504.0, "f97bff",
    100000.0, "fa47c35000",
    3.4028234663852886e+38, "fa7f7fffff",
    1.0e+300, "fb7e37e43c8800759c",
    5.960464477539063e-8, "f90001",
    0.00006103515625, "f90400",
    -4.0, "f9c400",
    -4.1, "fbc010666666666666",
    Infinity, "f97c00",
    NaN, "f97e00",
    -Infinity, "f9fc00",
    Infinity, "fa7f800000",
    NaN, "fa7fc00000",
    -Infinity, "faff800000",
    Infinity, "fb7ff0000000000000",
    NaN, "fb7ff8000000000000",
    -Infinity, "fbfff0000000000000",
    false, "f4",
    true, "f5",
    null, "f6",
    undefined, "f7",
    new Simple(16), "f0",
    new Simple(24), "f818",
    new Simple(255), "f8ff",
    new Date("2013-03-21T20:04:00Z"), "c074323031332d30332d32315432303a30343a30305a",
    new Date(1363896240 * 1000), "c11a514b67b0",
    new Date(1363896240.5 * 1000), "c1fb41d452d9ec200000",
    new Tagged(23, new Uint8Array([1, 2, 3, 4])), "d74401020304",
    new Tagged(24, new Uint8Array([0x64, 0x49, 0x45, 0x54, 0x46])), "d818456449455446",
    new Tagged(32, "http://www.example.com"), "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
    new Uint8Array(0), "40",
    new Uint8Array([1, 2, 3, 4]), "4401020304",
    "", "60",
    "a", "6161",
    "IETF", "6449455446",
    "\"\\", "62225c",
    "\u00fc", "62c3bc",
    "\u6c34", "63e6b0b4",
    "\ud800\udd51", "64f0908591",
    [], "80",
    [1, 2, 3], "83010203",
    [1, [2, 3], [4, 5]], "8301820203820405",
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25], "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
    {}, "a0",
    { 1: 2, 3: 4 }, "a201020304", // in JS keys are always strings
    { "a": 1, "b": [2, 3] }, "a26161016162820203",
    ["a", { "b": "c" }], "826161a161626163",
    { "a": "A", "b": "B", "c": "C", "d": "D", "e": "E" }, "a56161614161626142616361436164614461656145",

    // Indefinite
    new Uint8Array([1, 2, 3, 4, 5]), "5f42010243030405ff",
    "streaming", "7f657374726561646d696e67ff",
    [], "9fff",
    [1, [2, 3], [4, 5]], "9f018202039f0405ffff",
    [1, [2, 3], [4, 5]], "9f01820203820405ff",
    [1, [2, 3], [4, 5]], "83018202039f0405ff",
    [1, [2, 3], [4, 5]], "83019f0203ff820405",
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
    "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
    { "a": 1, "b": [2, 3] }, "bf61610161629f0203ffff",

    // Additional tests
    0.333251953125, "f93555",
    /^a[bc]+$/gi, "d8236c2f5e615b62635d2b242f6769"
];

describe("cbor", () => {
    it("should encode and decode", () => {

        const v = {
            "one": 1,
            "example array": [
                new Uint8Array([1, 2, 3]),
                "hello",
                42,
                -123456789,
                123.456,
                144115188075855870
            ],
            "created": new Date("2016-05-14T16:44:15.000Z")
        };

        const encoded = encode(v);
        const decoded = decode(encoded);

        expect(decoded).toEqual(v);
    });

    it("should correctly encode test vectors", () => {
        for (let i = 0; i < encoderTestVectors.length; i += 2) {
            const value = encoderTestVectors[i];
            const expected = encoderTestVectors[i + 1] as string;
            const got = encode(value);
            expect(hex.encode(got, true)).toBe(expected);
        }
    });

    it("should correctly decode test vectors", () => {
        for (let i = 0; i < decoderTestVectors.length; i += 2) {
            const expected = decoderTestVectors[i];
            const value = hex.decode(decoderTestVectors[i + 1] as string);
            const got = decode(value);
            expect(got).toEqual(expected);
        }
    });

    it("should encode and decode -0.0", () => {
        const encoded = encode(-0.0);
        const decoded = decode(encoded);
        expect(1 / decoded).toBe(-Infinity);
    });

    it("should throw if 64-bit integer is too large", () => {
        const vectors = [
            "1bffffffffffffffff", // 18446744073709551615
            "3bffffffffffffffff", // -18446744073709551616
        ];
        vectors.forEach(v => {
            expect(() => decode(hex.decode(v))).toThrowError(/too large/);
        });
    });

    it("should throw if there's extra data and the end", () => {
        const encoded = concat(encode("Hello world"), new Uint8Array(1));
        expect(() => decode(encoded)).toThrowError(/extra/);
    });

    it("should throw for objects cycles", () => {
        const a: { [key: string]: any } = { "one": 1 };
        const b: { [key: string]: any } = { "two": 2 };
        // create cycle
        b["a"] = a;
        a["b"] = b;
        // We expect JS runtime to throw "Maximum call stack size exceeded" error.
        expect(() => encode(a)).toThrowError(/call stack/);
        expect(() => encode(["insideArray", a])).toThrowError(/call stack/);
        expect(() => encode({ "insideObject": a })).toThrowError(/call stack/);
    });

    it("should encode maps with integer keys differently from string keys", () => {
        const a: { [key: string]: any } = { 1: "one", 2: "two", "3str": "three" };
        const eai = encode(a, { intKeys: true });
        // make sure it decodes
        const dec = decode(eai);
        expect(dec).toEqual(a);
        // make sure it differs from string encoding
        expect(encode(a)).not.toEqual(eai);
    });

    it("should encode and decode custom tagged object", () => {
        class Hello {
            greeting: string;
            constructor(g: string) {
                this.greeting = g;
            }
            get() {
                return this.greeting;
            }
        }

        const HelloEncoder: TaggedEncoder<Hello> =
            h => {
                if (!(h instanceof Hello)) {
                    return undefined;
                }
                return new Tagged(7777, h.get());
            };

        const HelloDecoder: TaggedDecoder<Hello> =
            ({ tag, value }) => {
                if (tag !== 7777) {
                    return undefined;
                }
                if (typeof value !== "string") {
                    throw new Error(`cbor: unexpected type for Hello string: "${typeof value}"`);
                }
                return new Hello(value);
            };

        const testData = {
            one: new Hello("world"),
            two: new Date(123)
        };

        const encodedData = encode(testData, {
            taggedEncoders: DEFAULT_TAGGED_ENCODERS.concat(HelloEncoder)
        });

        const decodedData = decode(encodedData, {
            taggedDecoders: DEFAULT_TAGGED_DECODERS.concat(HelloDecoder)
        });

        expect(decodedData.one instanceof Hello).toBeTruthy();
        expect(decodedData.one.greeting).toEqual(testData.one.greeting);
        expect(decodedData.two instanceof Date).toBeTruthy();
    });

});
