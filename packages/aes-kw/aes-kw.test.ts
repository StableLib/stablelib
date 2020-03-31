// Copyright (C) 2020 Tobias Looker
// MIT License. See LICENSE file for details.

import { AESKW } from "./aes-kw";
import { encode, decode } from "@stablelib/hex";

// Test vectors sourced from RFC 3394
// @see https://tools.ietf.org/html/rfc3394
const testVectors = [
    {
        Description: "128 bits of Key Data with a 128-bit KEK",
        KEK: "000102030405060708090A0B0C0D0E0F",
        KeyData: "00112233445566778899AABBCCDDEEFF",
        WrappedKey: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
    },
    {
        Description: "128 bits of Key Data with a 192-bit KEK",
        KEK: "000102030405060708090A0B0C0D0E0F1011121314151617",
        KeyData: "00112233445566778899AABBCCDDEEFF",
        WrappedKey: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"
    },
    {
        Description: "128 bits of Key Data with a 256-bit KEK",
        KEK: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        KeyData: "00112233445566778899AABBCCDDEEFF",
        WrappedKey: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"
    },
    {
        Description: "192 bits of Key Data with a 192-bit KEK",
        KEK: "000102030405060708090A0B0C0D0E0F1011121314151617",
        KeyData: "00112233445566778899AABBCCDDEEFF0001020304050607",
        WrappedKey: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"
    },
    {
        Description: "192 bits of Key Data with a 256-bit KEK",
        KEK: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        KeyData: "00112233445566778899AABBCCDDEEFF0001020304050607",
        WrappedKey: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
    },
    {
        Description: "256 bits of Key Data with a 256-bit KEK",
        KEK: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        KeyData: "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        WrappedKey: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    }
];

const keyEncryptionKey = "000102030405060708090A0B0C0D0E0F";
const tooShortKeyData = "001122334455";

describe("wrapKey", () => {
    testVectors.forEach(v => {
        it(`should wrap ${v.Description}`, () => {
            const aeskw = new AESKW(decode(v.KEK));
            const wrappedKey = aeskw.wrapKey(decode(v.KeyData));
            expect(encode(wrappedKey)).toBe(v.WrappedKey);
        });
    });

    it("should throw an error wrapping keyData that does not have sufficient length", () => {
        const aeskw = new AESKW(decode(keyEncryptionKey));
        expect(() => aeskw.wrapKey(decode(tooShortKeyData)))
                          .toThrowError(/16 bytes/);
    });
});

describe("unWrapKey", () => {
    testVectors.forEach(v => {
        it(`should unWrap ${v.Description}`, () => {
            const aeskw = new AESKW(decode(v.KEK));
            const keyData = aeskw.unwrapKey(decode(v.WrappedKey));
            expect(encode(keyData)).toBe(v.KeyData);
        });
    });

    it("should throw an error un-wrapping a wrapped key that does not have sufficient length", () => {
        const aeskw = new AESKW(decode(keyEncryptionKey));
        expect(() => aeskw.unwrapKey(decode(tooShortKeyData)))
                          .toThrowError(/16 bytes/);
    });

    it("should throw an error unWrapping a wrapped key that does not contain the default IV", () => {
        const aeskw = new AESKW(decode(keyEncryptionKey));
        expect(() => aeskw.unwrapKey(decode("E2EF32C0BBC36B6D236C2FD28E68FCDA8E24204C59F98754889D1ED24364A4D130AF535D350B9243")))
                          .toThrowError(/integrity/);
    });
});
