// Copyright (C) 2026 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from 'vitest';
import { PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, verify } from "./ed25519.js";

type VectorResult = "valid" | "invalid" | "acceptable";

type TestVector = {
    tcId: number;
    result: VectorResult;
    msg: string;
    sig: string;
};

type TestGroup = {
    publicKey: { pk: string };
    tests: TestVector[];
};

const vectorsUrl = new URL("./test-vectors/ed25519_test.json", import.meta.url);
const vectorsFile = existsSync(vectorsUrl)
    ? vectorsUrl
    : new URL("../test-vectors/ed25519_test.json", import.meta.url);
const vectors = JSON.parse(readFileSync(vectorsFile, "utf8")) as { testGroups: TestGroup[] };

function verifyVector(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    try {
        return verify(publicKey, message, signature);
    } catch (error) {
        // StableLib rejects wrong-sized keys and signatures by throwing from verify().
        if (
            error instanceof Error &&
            (error.message === `ed25519: public key must be ${PUBLIC_KEY_LENGTH} bytes` ||
                error.message === `ed25519: signature must be ${SIGNATURE_LENGTH} bytes`)
        ) {
            return false;
        }
        throw error;
    }
}

describe("Wycheproof test vectors", () => {
    for (const [groupIndex, group] of vectors.testGroups.entries()) {
        const publicKey = Buffer.from(group.publicKey.pk, "hex");

        for (const test of group.tests) {
            it(`should verify group ${groupIndex}, tcId ${test.tcId}`, () => {
                const verified = verifyVector(
                    publicKey,
                    Buffer.from(test.msg, "hex"),
                    Buffer.from(test.sig, "hex"),
                );

                if (test.result === "acceptable") {
                    expect(typeof verified).toBe("boolean");
                } else {
                    expect(verified).toBe(test.result === "valid");
                }
            });
        }
    }
});
