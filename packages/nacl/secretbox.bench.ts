// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { secretBox } from "./secretbox";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

const buf8192 = byteSeq(8192);
const buf1111 = byteSeq(1111);

const key = byteSeq(32);
const nonce = byteSeq(24);

report("secretBox 8K", benchmark(() => secretBox(key, nonce, buf8192), buf8192.length));
report("secretBox 1111", benchmark(() => secretBox(key, nonce, buf1111), buf1111.length));
