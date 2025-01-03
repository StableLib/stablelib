// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { splitRaw, combineRaw, split, combine } from "./tss.js";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

const secret = byteSeq(32);
const threshold = 5;
const totalShares = 10;
const rawShares = splitRaw(secret, threshold, totalShares);
const shares = split(secret, threshold, totalShares);

report("tss.combineRaw", benchmark(() => combineRaw(rawShares, threshold)));
report("tss.combine", benchmark(() => combine(shares)));
report("tss.splitRaw", benchmark(() => splitRaw(secret, threshold, totalShares)));
report("tss.split", benchmark(() => split(secret, threshold, totalShares)));
