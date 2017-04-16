// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { encode, decode } from "./hex";

let buf = new Uint8Array(256);
for (let i = 0; i < buf.length; i++) {
    buf[i] = i & 0xff;
}

let encBuf =
    "000102030405060708090A0B0C0D0E0F" +
    "101112131415161718191A1B1C1D1E1F" +
    "202122232425262728292A2B2C2D2E2F" +
    "303132333435363738393A3B3C3D3E3F" +
    "404142434445464748494A4B4C4D4E4F" +
    "505152535455565758595A5B5C5D5E5F" +
    "606162636465666768696A6B6C6D6E6F" +
    "707172737475767778797A7B7C7D7E7F" +
    "808182838485868788898A8B8C8D8E8F" +
    "909192939495969798999A9B9C9D9E9F" +
    "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
    "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
    "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF" +
    "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF" +
    "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF" +
    "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";



describe("hex.encode", () => {

    it("should encode data", () => {
        expect(encode(buf)).toEqual(encBuf);
    });

    it("should encode data to lower case", () => {
        expect(encode(buf, true)).toEqual(encBuf.toLowerCase());
    });

    it("should decode string", () => {
        expect(decode(encBuf)).toEqual(buf);
    });

    it("should decode lowercase string", () => {
        expect(decode(encBuf.toLowerCase())).toEqual(buf);
    });

    it("should throw if string is not divisible by 2", () => {
        expect(() => decode(encBuf + "1")).toThrowError("hex: input string must be divisible by two");
    });

    it("should throw if string contains invalid characters", () => {
        expect(() => decode(encBuf + "1x")).toThrowError("hex: incorrect characters for decoding");
    });

});
