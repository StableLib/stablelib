// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { RandomSource } from "@stablelib/random";
import { encode } from "@stablelib/hex";
import { X25519Session } from './keyagreement';

// For testing with generated test vectors, instead of proper PRNG
// use the deterministic generator that generates byte sequences
// of 0, 1, 2, 3, ... that was used to create vectors.
class BadSource implements RandomSource {
    isAvailable = true;

    constructor(private v = 0) { }

    randomBytes(length: number): Uint8Array {
        const out = new Uint8Array(length);
        for (let i = 0; i < out.length; i++) {
            out[i] = this.v;
            this.v = (this.v + 1) & 0xff;
        }
        return out;
    }
}

const testVector = {
    offerMsg:
    "8F40C5ADB68F25624AE5B214EA767A6EC94D829D3D7B5E1AD1BA6F3E2138285F",

    acceptMsg:
    "79A631EEDE1BF9C98F12032CDEADD0E7A079398FC786B88CC846EC89AF85A51A",

    sharedKey:
    "6D54CC9C397E31691401110F58DA1E182A635D7E44C21DC2D7BE93624652AB15"
};

describe("X25519Session", () => {
    it("should establish a shared secret and session keys", () => {
        for (let i = 0; i < 5; i++) {
            const server = new X25519Session();
            const offerMsg = server.offer();

            const client = new X25519Session();
            const acceptMsg = client.accept(offerMsg);

            server.finish(acceptMsg);

            const serverKey = server.getSharedKey();
            const clientKey = client.getSharedKey();

            expect(encode(serverKey)).toEqual(encode(clientKey));

            const serverSessionKeys = server.getSessionKeys();
            const clientSessionKeys = client.getSessionKeys();

            expect(encode(serverSessionKeys.send)).not.toEqual(encode(serverSessionKeys.receive));
            expect(encode(serverSessionKeys.send)).toEqual(encode(clientSessionKeys.receive));
            expect(encode(serverSessionKeys.receive)).toEqual(encode(clientSessionKeys.send));
        }
    });

    it("should match test vector", () => {
        const serverPrng = new BadSource(0);
        const server = new X25519Session(undefined, serverPrng);
        const offerMsg = server.offer();
        expect("offerMsg: " + encode(offerMsg))
            .toEqual("offerMsg: " + testVector.offerMsg);

        const clientPrng = new BadSource(64);
        const client = new X25519Session(undefined, clientPrng);
        const acceptMsg = client.accept(offerMsg);
        expect("acceptMsg: " + encode(acceptMsg))
            .toEqual("acceptMsg: " + testVector.acceptMsg);

        server.finish(acceptMsg);

        expect(encode(server.getSharedKey())).toEqual(testVector.sharedKey);
        expect(encode(client.getSharedKey())).toEqual(testVector.sharedKey);
    });
});
