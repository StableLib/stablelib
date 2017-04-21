// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { deriveKey, deriveKeyNonBlocking, Scrypt } from "./scrypt";
import { benchmarkPromise, report, byteSeq } from "@stablelib/benchmark";

(async () => {

    let password = byteSeq(14);
    let salt = byteSeq(32);

    report("scrypt 1024, 8, 1                        ",
        await benchmarkPromise(() => deriveKey(password, salt, 1024, 8, 1, 32)));

    report("scrypt 32768, 8, 1                       ",
        await benchmarkPromise(() => deriveKey(password, salt, 32768, 8, 1, 32)));

    report("scrypt 2**18, 8, 1                       ",
        await benchmarkPromise(() => deriveKey(password, salt, 2 ** 18, 8, 1, 32)));

    let inst = new Scrypt(32768, 8, 1);
    report("scrypt 32768, 8, 1 (shared)              ",
        await benchmarkPromise(() => inst.deriveKey(password, salt, 32)));


    report("scrypt 1024, 8, 1 (non-blocking)         ",
        await benchmarkPromise(() => deriveKeyNonBlocking(password, salt, 1024, 8, 1, 32)));

    report("scrypt 32768, 8, 1 (non-blocking)        ",
        await benchmarkPromise(() => deriveKeyNonBlocking(password, salt, 32768, 8, 1, 32)));

    report("scrypt 2**18, 8, 1 (non-blocking)        ",
        await benchmarkPromise(() => deriveKeyNonBlocking(password, salt, 2 ** 18, 8, 1, 32)));

    inst = new Scrypt(32768, 8, 1);
    report("scrypt 32768, 8, 1 (non-blocking, shared)",
        await benchmarkPromise(() => inst.deriveKeyNonBlocking(password, salt, 32)));
})();

