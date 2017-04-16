// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { AES } from "@stablelib/aes";
import { GCM } from "./gcm";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

const buf8192 = byteSeq(8192);
const buf1111 = byteSeq(1111);
const buf0 = new Uint8Array(0);

const key = byteSeq(32);
const nonce = byteSeq(12);

const cipher = new AES(key);
const gcm = new GCM(cipher);

report("AES-GCM seal 8K", benchmark(() => gcm.seal(nonce, buf8192), buf8192.length));
report("AES-GCM seal 1111", benchmark(() => gcm.seal(nonce, buf1111), buf1111.length));
report("AES-GCM seal 8K + AD", benchmark(() => gcm.seal(nonce, buf8192, buf8192), buf8192.length * 2));
report("AES-GCM seal 1111 + AD", benchmark(() => gcm.seal(nonce, buf1111, buf1111), buf1111.length * 2));
report("AES-GCM seal 0 + AD 8K", benchmark(() => gcm.seal(nonce, buf0, buf8192), buf8192.length));


const sealed8192 = gcm.seal(nonce, buf8192);
const sealed1111 = gcm.seal(nonce, buf1111);
const sealed8192ad = gcm.seal(nonce, buf8192, buf8192);
const sealed1111ad = gcm.seal(nonce, buf1111, buf1111);

report("AES-GCM open 8K", benchmark(() => gcm.open(nonce, sealed8192), buf8192.length));
report("AES-GCM open 1111", benchmark(() => gcm.open(nonce, sealed1111), buf1111.length));
report("AES-GCM open 8K + AD", benchmark(() => gcm.open(nonce, sealed8192ad, buf8192), buf8192.length * 2));
report("AES-GCM open 1111 + AD", benchmark(() => gcm.seal(nonce, sealed1111ad, buf1111), buf1111.length * 2));

sealed8192[0] ^= sealed8192[0];

report("AES-GCM open (bad)", benchmark(() => gcm.open(nonce, sealed8192), buf8192.length));
