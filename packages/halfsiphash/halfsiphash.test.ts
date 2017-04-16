// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import * as hex from "@stablelib/hex";
import { halfSipHash } from "./halfsiphash";

const testVectors = [
    "A9359F5B",
    "27475AB8",
    "FA62A603",
    "8AFEE704",
    "2A6E4689",
    "C5FAB669",
    "5863FC23",
    "8BCF63C5",
    "D0B8848F",
    "F806E779",
    "94B07934",
    "08083050",
    "57F0872F",
    "77E663FF",
    "D6FFF87C",
    "74FE2B97",
    "D9B5AC84",
    "C474645B",
    "465B8D9B",
    "7BEFE387",
    "E34D1045",
    "613F62B3",
    "70F367FE",
    "E6ADB8BD",
    "27400C63",
    "26787875",
    "4F567B5F",
    "3AB0E669",
    "B0644000",
    "FF670FB4",
    "509E338B",
    "5D589F1A",
    "FEE72112",
    "33753259",
    "6A434F8C",
    "FE28B729",
    "E75CC6EC",
    "697E8D54",
    "63688B0F",
    "650B62B4",
    "B6BC1840",
    "5D074505",
    "2442FD2E",
    "7BB7863A",
    "7705D548",
    "D75208B1",
    "B6D499C8",
    "0892202E",
    "69E12CE3",
    "8DB580E5",
    "369764C6",
    "016E0204",
    "3B85F3D4",
    "FEDB66BE",
    "1E692A3A",
    "C68984C0",
    "A5C5B940",
    "9BE9E88C",
    "7DBC8140",
    "7C078EC5",
    "D4E76C73",
    "428FCBB9",
    "BD83997A",
    "59EA4A74"
];

describe("halfSipHash", () => {
    it("should correctly produce test vectors", () => {
        // key is 1, 2, 3 ...
        const key = new Uint8Array(8);
        for (let i = 0; i < key.length; i++) {
            key[i] = i;
        }
        const inp = new Uint8Array(64);

        testVectors.forEach((correct, i) => {
            inp[i] = i;
            const sum = halfSipHash(key, inp.subarray(0, i));
            expect(hex.encode(sum)).toEqual(correct);
        });

    });
});
