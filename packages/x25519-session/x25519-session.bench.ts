// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { X25519Session } from "./keyagreement";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

const r = new Uint8Array(32); r[0] = 1;

const seed = byteSeq(32);

const offerMsg = new X25519Session(seed).offer();
const acceptMsg = new X25519Session(seed).accept(offerMsg);

report("X25519Session offer/finish", benchmark(() => {
    const state = new X25519Session(seed);
    state.offer();
    state.finish(acceptMsg);
}));

report("X25519Session accept", benchmark(() =>
    new X25519Session(seed).accept(offerMsg)));
