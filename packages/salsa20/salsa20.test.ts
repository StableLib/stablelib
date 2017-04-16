// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { streamXOR, stream } from "./salsa20";
import { encode, decode } from "@stablelib/hex";

function seq(len: number): Uint8Array {
    const x = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        x[i] = i & 0xff;
    }
    return x;
}

describe("salsa20.streamXOR", () => {
    const key = seq(32);
    const nonce8 = seq(8);

    it("should decrypt what it encrypted (17-byte input)", () => {
        const original = seq(17);
        const encrypted = new Uint8Array(original.length);
        const decrypted = new Uint8Array(original.length);

        streamXOR(key, nonce8, original, encrypted);
        expect(encrypted).not.toEqual(original);

        streamXOR(key, nonce8, encrypted, decrypted);
        expect(decrypted).toEqual(original);
    });

    it("should decrypt what it encrypted (155-byte input)", () => {
        const original = seq(155);
        const encrypted = new Uint8Array(original.length);
        const decrypted = new Uint8Array(original.length);

        streamXOR(key, nonce8, original, encrypted);
        expect(encrypted).not.toEqual(original);

        streamXOR(key, nonce8, encrypted, decrypted);
        expect(decrypted).toEqual(original);
    });

});

const vectors = [
    {
        key: "0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D",
        nonce: "0D74DB42A91077DE",
        length: 131072,
        xorDigest: "C349B6A51A3EC9B712EAED3F90D8BCEE69B7628645F251A996F55260C62E" +
        "F31FD6C6B0AEA94E136C9D984AD2DF3578F78E457527B03A0450580DD874F63B1AB9"
    },
    {
        key: "0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12",
        nonce: "167DE44BB21980E7",
        length: 131072,
        xorDigest: "C3EAAF32836BACE32D04E1124231EF47E101367D6305413A0EEB07C60698" +
        "A2876E4D031870A739D6FFDDD208597AFF0A47AC17EDB0167DD67EBA84F1883D4DFD",
    },
    {
        key: "0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417",
        nonce: "1F86ED54BB2289F0",
        length: 131072,
        xorDigest: "3CD23C3DC90201ACC0CF49B440B6C417F0DC8D8410A716D5314C059E14B1A" +
        "8D9A9FB8EA3D9C8DAE12B21402F674AA95C67B1FC514E994C9D3F3A6E41DFF5BBA6",
    },
    {
        key: "0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C",
        nonce: "288FF65DC42B92F9",
        length: 131072,
        xorDigest: "E00EBCCD70D69152725F9987982178A2E2E139C7BCBE04CA8A0E99E318D9A" +
        "B76F988C8549F75ADD790BA4F81C176DA653C1A043F11A958E169B6D2319F4EEC1A"
    }
];

describe("salsa20.stream", () => {
    it("should generate test vectors", () => {
        vectors.forEach(v => {
            const key = decode(v.key);
            const nonce = decode(v.nonce);
            const dst = stream(key, nonce, new Uint8Array(v.length));
            const xorDigest = new Uint8Array(64);
            let i = 0;
            while (i < dst.length) {
                for (let j = 0; j < 64; j++) {
                    xorDigest[j] ^= dst[i++];
                }
            }
            expect(encode(xorDigest)).toBe(v.xorDigest);
        });
    });
});

// TODO(dchest): test nonceInplaceCounterLength
