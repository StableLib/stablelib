// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { encode, decode, Tagged } from "./cbor";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

const buf = byteSeq(128);

const value = {
    someBytes: buf,
    someString: "this is a string needed to benchmark CBOR encoder and decoder",
    someNumbersInArray: [
        0.1234,
        1.1,
        3.4028234663852886e+38,
        65536,
        232992399333333,
        Infinity
    ],
    someBoolean: true,
    someUndefined: undefined,
    someObject: {
        someNullsAndTagged: [null, null, null, new Tagged(32, "something")],
        anotherString: "hey",
        anotherBytes: new Uint8Array([1, 2, 3]),
        date: new Date(0),
        regexp: /^a[bc]+/gi
    }
};

const encodedValue = encode(value);
const bigBuf = byteSeq(1024);
const encodedBigBuf = encode(bigBuf);

// Benchmark report MiB/s for encoded MiB.
report("CBOR encode", benchmark(() => encode(value), encodedValue.length));
report("CBOR decode", benchmark(() => decode(encodedValue), encodedValue.length));
report("CBOR encode bytes", benchmark(() => encode(bigBuf), bigBuf.length));
report("CBOR decode bytes", benchmark(() => decode(encodedBigBuf), encodedBigBuf.length));

// JSON for comparison

const jsonEncodedValue = JSON.stringify(value);

report("JSON encode", benchmark(() => JSON.stringify(value), encodedValue.length));
report("JSON decode", benchmark(() => JSON.parse(jsonEncodedValue), encodedValue.length));
