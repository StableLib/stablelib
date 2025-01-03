// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { streamXOR } from "./salsa20.js";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

const buf8192 = byteSeq(8192);
const buf1111 = byteSeq(1111);

const key = byteSeq(32);
const nonce = byteSeq(8);

report("Salsa20/20 xor 8K", benchmark(() => streamXOR(key, nonce, buf8192, buf8192), buf8192.length));
report("Salsa20/20 xor 1111", benchmark(() => streamXOR(key, nonce, buf1111, buf1111), buf1111.length));
