// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { XChaCha20Poly1305 } from "./xchacha20poly1305";
import { encode, decode } from "@stablelib/hex";

const testVectors = [
    /**
     *  Test vector from draft-irtf-cfrg-xchacha
     *  see https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01#appendix-A.3.1
     *  tag value is appended to the result (aka ciphertext)
     */
    {
        key: "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
        nonce: "404142434445464748494a4b4c4d4e4f5051525354555657",
        aad: "50515253C0C1C2C3C4C5C6C7",
        plaintext:
            "4C616469657320616E642047656E746C656D656E206F662074686520636C617373206F66" +
            "202739393A204966204920636F756C64206F6666657220796F75206F6E6C79206F6E6520" +
            "74697020666F7220746865206675747572652C2073756E73637265656E20776F756C6420" +
            "62652069742E",
        result:
            "BD6D179D3E83D43B9576579493C0E939" +
            "572A1700252BFACCBED2902C21396CBB" +
            "731C7F1B0B4AA6440BF3A82F4EDA7E39" +
            "AE64C6708C54C216CB96B72E1213B452" +
            "2F8C9BA40DB5D945B11B69B982C1BB9E" +
            "3F3FAC2BC369488F76B2383565D3FFF9" +
            "21F9664C97637DA9768812F615C68B13" +
            "B52EC0875924C1C7987947DEAFD8780A" +
            "CF49",
    }
];

// TODO(dchest): add more various tests.

describe("XChaCha20Poly1305", () => {
    it("should correctly seal", () => {
        testVectors.forEach(v => {
            const aead = new XChaCha20Poly1305(decode(v.key));
            const sealed = aead.seal(decode(v.nonce), decode(v.plaintext), v.aad ? decode(v.aad) : undefined);
            expect(encode(sealed)).toBe(v.result);
        });
    });

    it("should correctly open", () => {
        testVectors.forEach(v => {
            const aead = new XChaCha20Poly1305(decode(v.key));
            const plaintext = aead.open(decode(v.nonce), decode(v.result), v.aad ? decode(v.aad) : undefined);
            expect(plaintext).not.toBeNull();
            if (plaintext) {
                expect(encode(plaintext)).toBe(v.plaintext);
            }
        });
    });

    it("should not open when ciphertext is corrupted", () => {
        const v = testVectors[0];
        const sealed = decode(v.result);
        sealed[0] ^= sealed[0];
        const aead = new XChaCha20Poly1305(decode(v.key));
        const plaintext = aead.open(decode(v.nonce), sealed, v.aad ? decode(v.aad) : undefined);
        expect(plaintext).toBeNull();
    });

    it("should not open when tag is corrupted", () => {
        const v = testVectors[0];
        const sealed = decode(v.result);
        sealed[sealed.length - 1] ^= sealed[sealed.length - 1];
        const aead = new XChaCha20Poly1305(decode(v.key));
        const plaintext = aead.open(decode(v.nonce), sealed, v.aad ? decode(v.aad) : undefined);
        expect(plaintext).toBeNull();
    });

    it("should seal to dst it is provided", () => {
        const v = testVectors[0];
        const aead = new XChaCha20Poly1305(decode(v.key));
        const plaintext = decode(v.plaintext);
        const ad = v.aad ? decode(v.aad) : undefined;
        const dst = new Uint8Array(plaintext.length + aead.tagLength);
        const sealed = aead.seal(decode(v.nonce), decode(v.plaintext), ad, dst);
        expect(encode(dst)).toBe(encode(sealed));
        expect(encode(sealed)).toBe(v.result);
    });

    it("should throw if seal got dst of wrong length", () => {
        const v = testVectors[0];
        const aead = new XChaCha20Poly1305(decode(v.key));
        const plaintext = decode(v.plaintext);
        const ad = v.aad ? decode(v.aad) : undefined;
        const dst = new Uint8Array(plaintext.length + aead.tagLength - 1); // wrong length
        expect(() =>
            aead.seal(decode(v.nonce), decode(v.plaintext), ad, dst)
        ).toThrowError(/length/);
    });

    it("should open to dst it is provided", () => {
        const v = testVectors[0];
        const aead = new XChaCha20Poly1305(decode(v.key));
        const sealed = decode(v.result);
        const ad = v.aad ? decode(v.aad) : undefined;
        const dst = new Uint8Array(sealed.length - aead.tagLength);
        const plaintext = aead.open(decode(v.nonce), decode(v.result), ad, dst);
        expect(plaintext).not.toBeNull();
        if (plaintext) {
            expect(encode(dst)).toBe(encode(plaintext));
            expect(encode(plaintext)).toBe(v.plaintext);
        }
    });

    it("should throw if open got dst of wrong length", () => {
        const v = testVectors[0];
        const aead = new XChaCha20Poly1305(decode(v.key));
        const sealed = decode(v.result);
        const ad = v.aad ? decode(v.aad) : undefined;
        const dst = new Uint8Array(sealed.length - aead.tagLength + 1); // wrong length
        expect(() =>
            aead.open(decode(v.nonce), decode(v.result), ad, dst)
        ).toThrowError(/length/);
    });
});

