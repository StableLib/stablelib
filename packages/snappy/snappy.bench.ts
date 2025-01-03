// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { benchmark, report } from "@stablelib/benchmark";
import { compress, maxCompressedLength } from "./compress.js";
import { decompress } from "./decompress.js";
import * as zlib from "zlib";
import data from "./compress.test-data.js";


const compressedData = compress(data);
const decompressedData = new Uint8Array(data.length);
const compressedDst = new Uint8Array(maxCompressedLength(data.length));

// console.log("Length: ", data.length, "/", compressedData.length);

report("Snappy compress", benchmark(() => compress(data, compressedDst), data.length));
report("Snappy decompress", benchmark(() => decompress(compressedData, decompressedData), data.length));

const zOpts = { level: zlib.constants.Z_BEST_SPEED, strategy: zlib.constants.Z_HUFFMAN_ONLY };
const zData = Buffer.from(data);
const zCompressedData = zlib.deflateSync(zData, zOpts);

report("zlib-1 compress", benchmark(() => zlib.deflateSync(zData, zOpts), zData.length));
report("zlib-1 decompress", benchmark(() => zlib.inflateSync(zCompressedData), zData.length));

console.log("Snappy compressed length:", compressedData.length);
console.log("zlib-1 compressed length:", zCompressedData.length);
