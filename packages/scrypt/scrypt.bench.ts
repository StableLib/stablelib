// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { deriveKey } from "./scrypt";
import { benchmarkPromise, report, byteSeq } from "@stablelib/benchmark";

(async () => {

    let password = byteSeq(14);
    let salt = byteSeq(32);

    report("scrypt 1024, 8, 1",
        await benchmarkPromise(() => deriveKey(password, salt, 1024, 8, 1, 32)));

    report("scrypt 32768, 8, 1",
        await benchmarkPromise(() => deriveKey(password, salt, 32768, 8, 1, 32)));

})();
