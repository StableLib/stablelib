// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { xof } from "./blake2xs";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

let key = byteSeq(32);
let data = byteSeq(32, 1);

report("BLAKE2Xs 8K out", benchmark(() => xof(8 << 10, data, key), 8 << 10));
report("BLAKE2Xs 64 out", benchmark(() => xof(64, data, key), 64));
