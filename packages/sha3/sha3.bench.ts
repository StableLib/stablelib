// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { hash256 } from "./sha3.js";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

let buf1M = byteSeq(1024 << 10);
let buf8K = byteSeq(8 << 10);
let buf1K = byteSeq(1 << 10);
let buf32 = byteSeq(32);

report("SHA3-256 1M", benchmark(() => hash256(buf1M), buf1M.length));
report("SHA3-256 8K", benchmark(() => hash256(buf8K), buf8K.length));
report("SHA3-256 1K", benchmark(() => hash256(buf1K), buf1K.length));
report("SHA3-256 32", benchmark(() => hash256(buf32), buf32.length));
