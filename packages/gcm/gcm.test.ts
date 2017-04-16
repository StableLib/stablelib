// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { AES } from "@stablelib/aes";
import { GCM } from "./gcm";
import { encode, decode } from "@stablelib/hex";

// TODO(dchest): add more test vectors.
const testVectors = [
    // Test vectors from Go implementation:
    // https://golang.org/src/crypto/cipher/gcm_test.go
    {
        key: "5394E890D37BA55EC9D5F327F15680F6A63EF5279C79331643AD0AF6D2623525",
        nonce: "815E840B7ACA7AF3B324583F",
        plaintext:
        "8E63067CD15359F796B43C68F093F55FDF3589FC5F2FDFAD5F9D156668A6" +
        "17F7091D73DA71CDD207810E6F71A165D0809A597DF9885CA6E8F9BB4E61" +
        "6166586B83CC45F49917FC1A256B8BC7D05C476AB5C4633E20092619C474" +
        "7B26DAD3915E9FD65238EE4E5213BADEDA8A3A22F5EFE6582D0762532026" +
        "C89B4CA26FDD000EB45347A2A199B55B7790E6B1B2DBA19833CE9F9522C0" +
        "BCEA5B088CCAE68DD99AE0203C81B9F1DD3181C3E2339E83CCD1526B6774" +
        "2B235E872BEA5111772AAB574AE7D904D9B6355A79178E179B5AE8EDC54F" +
        "61F172BF789EA9C9AF21F45B783E4251421B077776808F04972A5E801723" +
        "CF781442378CE0E0568F014AEA7A882DCBCB48D342BE53D1C2EBFB206B12" +
        "443A8A587CC1E55CA23BECA385D61D0D03E9D84CBC1B0A",
        ad: "0FECCDFAE8ED65FA31A0858A1C466F79E8AA658C2F3BA93C3F92158B4E30955E1C62580450BEFF",
        result:
        "B69A7E17BB5AF688883274550A4DED0D1AFF49A0B18343F4B382F745C163" +
        "F7F714C9206A32A1FF012427E19431951EDD0A755E5F491B0EEDFD7DF68B" +
        "BC6085DD2888607A2F998C3E881EB1694109250DB28291E71F4AD344A125" +
        "624FB92E16EA9815047CD1111CABFDC9CB8C3B4B0F40AA91D31774009781" +
        "231400789ED545404AF6C3F76D07DDC984A7BD8F52728159782832E298CC" +
        "4D529BE96D17BE898EFD83E44DC7B0E2EFC645849FD2BBA61FEF0AE7BE0D" +
        "CAB233CC4E2B7BA4E887DE9C64B97F2A1818AA54371A8D629DAE37975F77" +
        "84E5E3CC77055ED6E975B1E5F55E6BBACDC9F295CE4ADA2C16113CD5B323" +
        "CF78B7DDE39F4A87AA8C141A31174E3584CCBD380CF5EC6D1DBA539928B0" +
        "84FA9683E9C0953ACF47CC3AC384A2C38914F1DA01FB2CFD78905C2B58D3" +
        "6B2574B9DF15535D82"
    },
    // Manually generated with Go implementation:
    {
        key: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        nonce: "202122232425262728292A2B",
        ad: undefined,
        plaintext:
        "2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464" + "748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162" +
        "636465666768696A6B",
        result:
        "FE17885F5CA9283D2E4974F9F921CEC2EC74D2A3C7C121AD28B32A5" +
        "501C3144239C3AB4BDE74678940A838C500504593BE77B2D1FA5D4F" +
        "02AA07197A24DB60B60C64C285646E4887166AA2DB826AF396",
    }
];

// TODO(dchest): add more various tests.

describe("AES-GCM", () => {
    it("should correctly seal", () => {
        testVectors.forEach(v => {
            const cipher = new AES(decode(v.key));
            const gcm = new GCM(cipher);
            let sealed: Uint8Array;
            if (v.ad) {
                sealed = gcm.seal(decode(v.nonce), decode(v.plaintext), decode(v.ad));
            } else {
                sealed = gcm.seal(decode(v.nonce), decode(v.plaintext));
            }
            expect(encode(sealed)).toBe(v.result);
        });
    });

    it("should correctly open", () => {
        testVectors.forEach(v => {
            const cipher = new AES(decode(v.key));
            const gcm = new GCM(cipher);
            let plaintext: Uint8Array | null;
            if (v.ad) {
                plaintext = gcm.open(decode(v.nonce), decode(v.result), decode(v.ad));
            } else {
                plaintext = gcm.open(decode(v.nonce), decode(v.result));
            }
            expect(plaintext).not.toBeNull();
            if (plaintext) {
                expect(encode(plaintext)).toBe(v.plaintext);
            }
        });
    });


    it("should not open when ciphertext is corrupted", () => {
        const v = testVectors[0];
        const sealed = decode(v.result);
        const ad = v.ad ? decode(v.ad) : undefined;
        sealed[0] ^= sealed[0];
        const cipher = new AES(decode(v.key));
        const gcm = new GCM(cipher);
        const plaintext = gcm.open(decode(v.nonce), sealed, ad);
        expect(plaintext).toBeNull();
    });

    it("should not open when tag is corrupted", () => {
        const v = testVectors[0];
        const sealed = decode(v.result);
        const ad = v.ad ? decode(v.ad) : undefined;
        sealed[sealed.length - 1] ^= sealed[sealed.length - 1];
        const cipher = new AES(decode(v.key));
        const gcm = new GCM(cipher);
        const plaintext = gcm.open(decode(v.nonce), sealed, ad);
        expect(plaintext).toBeNull();
    });

    it("should seal to dst it is provided", () => {
        const v = testVectors[0];
        const cipher = new AES(decode(v.key));
        const gcm = new GCM(cipher);
        const plaintext = decode(v.plaintext);
        const ad = v.ad ? decode(v.ad) : undefined;
        const dst = new Uint8Array(plaintext.length + gcm.tagLength);
        const sealed = gcm.seal(decode(v.nonce), decode(v.plaintext), ad, dst);
        expect(encode(dst)).toBe(encode(sealed));
        expect(encode(sealed)).toBe(v.result);
    });

    it("should throw if seal got dst of wrong length", () => {
        const v = testVectors[0];
        const cipher = new AES(decode(v.key));
        const gcm = new GCM(cipher);
        const plaintext = decode(v.plaintext);
        const ad = v.ad ? decode(v.ad) : undefined;
        const dst = new Uint8Array(plaintext.length + gcm.tagLength - 1); // wrong length
        expect(() =>
            gcm.seal(decode(v.nonce), decode(v.plaintext), ad, dst)
        ).toThrowError(/length/);
    });

    it("should open to dst it is provided", () => {
        const v = testVectors[0];
        const cipher = new AES(decode(v.key));
        const gcm = new GCM(cipher);
        const sealed = decode(v.result);
        const ad = v.ad ? decode(v.ad) : undefined;
        const dst = new Uint8Array(sealed.length - gcm.tagLength);
        const plaintext = gcm.open(decode(v.nonce), decode(v.result), ad, dst);
        expect(plaintext).not.toBeNull();
        if (plaintext) {
            expect(encode(dst)).toBe(encode(plaintext));
            expect(encode(plaintext)).toBe(v.plaintext);
        }
    });

    it("should throw if open got dst of wrong length", () => {
        const v = testVectors[0];
        const cipher = new AES(decode(v.key));
        const gcm = new GCM(cipher);
        const sealed = decode(v.result);
        const ad = v.ad ? decode(v.ad) : undefined;
        const dst = new Uint8Array(sealed.length - gcm.tagLength + 1); // wrong length
        expect(() =>
            gcm.open(decode(v.nonce), decode(v.result), ad, dst)
        ).toThrowError(/length/);
    });
});

