// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { hash } from "./blake2b";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

let buf1M = byteSeq(1024 << 10);
let buf8K = byteSeq(8 << 10);
let buf1K = byteSeq(1 << 10);
let buf32 = byteSeq(32);

report("BLAKE2b 1M", benchmark(() => hash(buf1M), buf1M.length));
report("BLAKE2b 8K", benchmark(() => hash(buf8K), buf8K.length));
report("BLAKE2b 1K", benchmark(() => hash(buf1K), buf1K.length));
report("BLAKE2b 32", benchmark(() => hash(buf32), buf32.length));
