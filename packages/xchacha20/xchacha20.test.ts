// Copyright (C) 2019 Kyle Den Hartog
// MIT License. See LICENSE file for details.

import { describe, expect, it } from 'vitest';
import { hchacha, stream, streamXOR } from "./xchacha20.js";
import { encode, decode } from "@stablelib/hex";

// test taken from draft-arciszewski-xchacha-03 section 2.2.1
// see https://tools.ietf.org/html/draft-arciszewski-xchacha-03#section-2.2.1
describe("xchacha20.hchacha", () => {
  it("should produce correct value", () => {
    const key = decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const nonce = decode("000000090000004A0000000031415927");
    const good = "82413B4227B27BFED30E42508A877D73A0F9E4D58A74A853C12EC41326D3ECDC";
    const dst = new Uint8Array(32);
    const subkey = hchacha(key, nonce.subarray(0, 16), dst);
    expect(encode(subkey)).toBe(good);
  });
});

// test taken from XChaCha20 TV1 in libsodium (line 93 in libsodium/test/default/xchacha20.c)
describe("xchacha20.stream", () => {
  it("should produce correct result", () => {
    const key = decode("79C99798AC67300BBB2704C95C341E3245F3DCB21761B98E52FF45B24F304FC4");
    const nonce = decode("B33FFD3096479BCFBC9AEE49417688A0A2554F8D95389419");
    const good = "C6E9758160083AC604EF90E712CE6E75D7797590744E0CF060F013739C";
    const dst = new Uint8Array(good.length / 2);
    expect(encode(stream(key, nonce, dst))).toBe(good);
  });
});

// test taken from draft-arciszewski-xchacha-03 section A.3.2
// see https://tools.ietf.org/html/draft-arciszewski-xchacha-03#appendix-A.3.2
describe("xchacha20.streamXOR", () => {
  it("should produce correct result", () => {
    const key = decode("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
    const plaintext = decode(
      "5468652064686F6C65202870726F6E6F756E6365642022646F6C652229206973" +
      "20616C736F206B6E6F776E2061732074686520417369617469632077696C6420" +
     "646F672C2072656420646F672C20616E642077686973746C696E6720646F672E" +
     "2049742069732061626F7574207468652073697A65206F662061204765726D61" +
     "6E20736865706865726420627574206C6F6F6B73206D6F7265206C696B652061" +
     "206C6F6E672D6C656767656420666F782E205468697320686967686C7920656C" +
     "757369766520616E6420736B696C6C6564206A756D70657220697320636C6173" +
     "736966696564207769746820776F6C7665732C20636F796F7465732C206A6163" +
     "6B616C732C20616E6420666F78657320696E20746865207461786F6E6F6D6963" +
     "2066616D696C792043616E696461652E"
    );
    const nonce = decode("404142434445464748494A4B4C4D4E4F5051525354555658");
    const ciphertext =
      "4559ABBA4E48C16102E8BB2C05E6947F" +
      "50A786DE162F9B0B7E592A9B53D0D4E9" +
      "8D8D6410D540A1A6375B26D80DACE4FA" +
      "B52384C731ACBF16A5923C0C48D3575D" +
      "4D0D2C673B666FAA731061277701093A" +
      "6BF7A158A8864292A41C48E3A9B4C0DA" +
      "ECE0F8D98D0D7E05B37A307BBB663331" +
      "64EC9E1B24EA0D6C3FFDDCEC4F68E744" +
      "3056193A03C810E11344CA06D8ED8A2B" +
      "FB1E8D48CFA6BC0EB4E2464B74814240" +
      "7C9F431AEE769960E15BA8B96890466E" +
      "F2457599852385C661F752CE20F9DA0C" +
      "09AB6B19DF74E76A95967446F8D0FD41" +
      "5E7BEE2A12A114C20EB5292AE7A349AE" +
      "577820D5520A1F3FB62A17CE6A7E68FA" +
      "7C79111D8860920BC048EF43FE84486C" +
      "CB87C25F0AE045F0CCE1E7989A9AA220" +
      "A28BDD4827E751A24A6D5C62D790A663" +
      "93B93111C1A55DD7421A10184974C7C5";
    const dst = new Uint8Array(ciphertext.length / 2);
    expect(encode(streamXOR(key, nonce, plaintext, dst))).toBe(ciphertext);
  });
});
