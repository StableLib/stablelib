// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import * as utf8 from "@stablelib/utf8";
import * as hex from "@stablelib/hex";
import { byteSeq } from "@stablelib/benchmark";
import { compress } from "./compress";
import { decompress } from "./decompress";
import bigTestData from "./compress.test-data";

const smallTestData = utf8.encode("aaaaaaaaaabbabbbabbbabbabccccccccbbbbbbbaaaaaaabbabbabba");
// generated with github.com/golang/snappy
const compressedSmallTestData = hex.decode("38006115010C626261621504086162630D01006209010D2720626261626261626261");

describe("Snappy", () => {
    it("should decompress small test data", () => {
        const decompressedData = decompress(compressedSmallTestData);
        expect(decompressedData).toEqual(smallTestData);
    });

    it("should compress and decompress small test data", () => {
        const compressedData = compress(smallTestData);
        const decompressedData = decompress(compressedData);
        expect(decompressedData).toEqual(smallTestData);
    });

    it("should compress and decompress big test data", () => {
        const compressedData = compress(bigTestData);
        const decompressedData = decompress(compressedData);
        expect(decompressedData).toEqual(bigTestData);
    });

    it("should compress and decompress small byte sequence", () => {
        const data = byteSeq(100);
        const compressedData = compress(data);
        const decompressedData = decompress(compressedData);
        expect(decompressedData).toEqual(data);
    });

    it("should compress and decompress small byte sequence", () => {
        const data = byteSeq(2 * 1024 << 10);
        const compressedData = compress(data);
        const decompressedData = decompress(compressedData);
        expect(decompressedData).toEqual(data);
    });

});
