// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { deriveKey } from "./pbkdf2";
import { SHA256 } from "@stablelib/sha256";
import { SHA512 } from "@stablelib/sha512";
import { SHA3512 } from "@stablelib/sha3";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

let password = byteSeq(14);
let salt = byteSeq(32);

report("pbkdf2/sha256 1", benchmark(() => deriveKey(SHA256, password, salt, 1, 32)));
report("pbkdf2/sha256 5000", benchmark(() => deriveKey(SHA256, password, salt, 5000, 32)));
report("pbkdf2/sha256 10000", benchmark(() => deriveKey(SHA256, password, salt, 10000, 32)));
report("pbkdf2/sha512 5000", benchmark(() => deriveKey(SHA512, password, salt, 5000, 64)));
report("pbkdf2/sha3-512 5000", benchmark(() => deriveKey(SHA3512, password, salt, 5000, 64)));
