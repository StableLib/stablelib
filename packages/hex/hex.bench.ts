// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { encode, decode } from "./hex";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

let buf = byteSeq(1024);
const encBuf = encode(buf);

report("Hex encode", benchmark(() => encode(buf), buf.length));
// Decode benchmark reports MiB/s for decoded MiB, not input.
report("Hex decode", benchmark(() => decode(encBuf), buf.length));
