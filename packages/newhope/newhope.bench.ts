// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { NewHope } from "./newhope.js";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

const seed = byteSeq(32);
const offerMsg = new NewHope(seed).offer(seed);
const acceptMsg = new NewHope(seed).accept(offerMsg);

report("NewHope-SHA3 offer/finish", benchmark(() => {
    const state = new NewHope(seed);
    state.offer(seed);
    state.finish(acceptMsg);
}));

report("NewHope-SHA3 accept", benchmark(() =>
    new NewHope(seed).accept(offerMsg)));
