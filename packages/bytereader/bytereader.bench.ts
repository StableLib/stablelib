// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { ByteReader } from "./bytereader";
import { report, benchmark, byteSeq } from "@stablelib/benchmark";

const buf = byteSeq(8 << 10);

report("ByteReader read", benchmark(() => benchmarkRead(buf), buf.length));
report("ByteReader readByte", benchmark(() => benchmarkReadByte(buf), buf.length));
report("ByteReader readUint32", benchmark(() => benchmarkReadUint32(buf), buf.length));
report("ByteReader readFloat64", benchmark(() => benchmarkReadFloat64(buf), buf.length));

function benchmarkRead(b: Uint8Array) {
    const r = new ByteReader(b);
    const n = b.length / 32;
    for (let i = 0; i < b.length; i += n) {
        r.read(n);
    }
}

function benchmarkReadByte(b: Uint8Array) {
    const r = new ByteReader(b);
    for (let i = 0; i < b.length; i++) {
        r.readByte();
    }
}

function benchmarkReadUint32(b: Uint8Array) {
    const r = new ByteReader(b);
    for (let i = 0; i < b.length; i += 4) {
        r.readUint32BE();
    }
}

function benchmarkReadFloat64(b: Uint8Array) {
    const r = new ByteReader(b);
    for (let i = 0; i < b.length; i += 8) {
        r.readFloat64BE();
    }
}
