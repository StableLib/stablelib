// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { halfSipHash } from "./halfsiphash";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

const buf1M = byteSeq(1024 << 10);
const buf8K = byteSeq(8 << 10);
const buf1K = byteSeq(1 << 10);
const buf32 = byteSeq(32);
const buf16 = byteSeq(16);
const buf8 = byteSeq(8);
const buf4 = byteSeq(4);
const buf3 = byteSeq(3);

const key = byteSeq(8);

report("halfSipHash 1M", benchmark(() => halfSipHash(key, buf1M), buf1M.length));
report("halfSipHash 8K", benchmark(() => halfSipHash(key, buf8K), buf8K.length));
report("halfSipHash 1K", benchmark(() => halfSipHash(key, buf1K), buf1K.length));
report("halfSipHash 32", benchmark(() => halfSipHash(key, buf32), buf32.length));
report("halfSipHash 16", benchmark(() => halfSipHash(key, buf16), buf16.length));
report("halfSipHash 8", benchmark(() => halfSipHash(key, buf8), buf8.length));
report("halfSipHash 4", benchmark(() => halfSipHash(key, buf4), buf4.length));
report("halfSipHash 3", benchmark(() => halfSipHash(key, buf3), buf3.length));
