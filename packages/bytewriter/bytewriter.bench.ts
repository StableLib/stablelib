// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { ByteWriter } from "./bytewriter";
import { report, benchmark, byteSeq } from "@stablelib/benchmark";

report("ByteWriter write", benchmark(() => benchmarkWrite(8192), 8192));
report("ByteWriter writeByte", benchmark(() => benchmarkWriteByte(8192), 8192));
report("ByteWriter writeUint32", benchmark(() => benchmarkWriteUint32(8192), 8192));
report("ByteWriter writeFloat64", benchmark(() => benchmarkWriteFloat64(8192), 8192));

function benchmarkWrite(n: number) {
    const b = byteSeq(n / 32);
    const w = new ByteWriter();
    for (let i = 0; i < n; i += 32) {
        w.write(b);
    }
    w.finish();
}

function benchmarkWriteByte(n: number) {
    const w = new ByteWriter();
    for (let i = 0; i < n; i++) {
        w.writeByte(0x7f);
    }
    w.finish();
}

function benchmarkWriteUint32(n: number) {
    const w = new ByteWriter();
    for (let i = 0; i < n; i += 4) {
        w.writeUint32BE(12345678);
    }
    w.finish();
}

function benchmarkWriteFloat64(n: number) {
    const w = new ByteWriter();
    for (let i = 0; i < n; i += 8) {
        w.writeUint32BE(12345.67890);
    }
    w.finish();
}
