// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

// Based on snappy-go: https://github.com/golang/snappy
// Copyright 2011 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// https://github.com/golang/snappy/blob/master/LICENSE

const TAG_LITERAL = 0x00;
const TAG_COPY1 = 0x01;
const TAG_COPY2 = 0x02;
const TAG_COPY4 = 0x03;

const CORRUPT = "snappy: corrupt block";
const TOOLARGE = "snappy: decoded block is too large";

// Maximum number of bytes that can be compressed at once.
// See maxCompressedLength() in compress.ts for details.
const MAX_INPUT_SIZE = 1840700241;

/**
 * Reads decompressed length from src and returns it.
 *
 * Throws an error if the length is too large or the input is corrupted.
 */
export function decompressedLength(src: Uint8Array): number {
    let origLen = 0;
    let shift = 0;
    let s = 0;
    for (; s < src.length; s++) {
        let b = src[s];
        if (b < 0x80) {
            if (s > 5 || (s === 5 && b > 1)) {
                throw new Error(TOOLARGE);
            }
            origLen |= (b << shift) >>> 0;
            s++;
            break;
        }
        origLen |= (b & 0x7f) << shift;
        shift += 7;
    }
    if (s === 0 || origLen > MAX_INPUT_SIZE) {
        throw new Error(CORRUPT);
    }
    return origLen;
}

/**
 * Decompresses src into dst and returns a subarray into dst containing
 * decompressed data.
 *
 * The length of decompress data is read from src. If dst is smaller than it,
 * the new appropriately sized dst is allocated and returned.
 *
 * Throws an error if input is corrupted.
 *
 * This is a bare block compression without any framing.
 */
export function decompress(src: Uint8Array, dst?: Uint8Array): Uint8Array {
    const slen = src.length;

    // Read length.
    let origLen = 0;
    let shift = 0;
    let s = 0;
    for (; s < slen; s++) {
        let b = src[s];
        if (b < 0x80) {
            if (s > 5 || (s === 5 && b > 1)) {
                throw new Error(TOOLARGE);
            }
            origLen |= (b << shift) >>> 0;
            s++;
            break;
        }
        origLen |= (b & 0x7f) << shift;
        shift += 7;
    }
    if (s === 0 || origLen > MAX_INPUT_SIZE) {
        throw new Error(CORRUPT);
    }

    if (!dst || dst.length < origLen) {
        dst = new Uint8Array(origLen);
    }
    const dlen = dst.length;

    let d = 0;
    let offset = 0;

    while (s < slen) {
        const op = src[s];
        let length = op >>> 2;
        switch (op & 0x03) {
            case TAG_LITERAL: {
                if (length < 60) {
                    s += 1;
                } else if (length === 60) {
                    s += 2;
                    if (s > slen) {
                        throw new Error(CORRUPT);
                    }
                    length = src[s - 1];
                } else if (length === 61) {
                    s += 3;
                    if (s > slen) {
                        throw new Error(CORRUPT);
                    }
                    length = src[s - 2] | (src[s - 1] << 8);
                } else if (length === 62) {
                    s += 4;
                    if (s > slen) {
                        throw new Error(CORRUPT);
                    }
                    length = src[s - 3] | (src[s - 2] << 8) | (src[s - 1] << 16);
                } else if (length === 63) {
                    s += 5;
                    if (s > slen) {
                        throw new Error(CORRUPT);
                    }
                    length = src[s - 4] | (src[s - 3] << 8) | (src[s - 2] << 16) | (src[s - 1] << 24);
                }
                length += 1;
                if (length <= 0) {
                    throw new Error("snappy: unsupported literal length");
                }
                if (length > dlen - d || length > slen - s) {
                    throw new Error(CORRUPT);
                }
                for (let j = 0; j < length; j++) {
                    dst[d + j] = src[s + j];
                }
                d += length;
                s += length;
                continue;
            }
            case TAG_COPY1: { // tslint:disable-line
                s += 2;
                if (s > slen) {
                    throw new Error(CORRUPT);
                }
                length = 4 + (length & 0x7);
                offset = ((src[s - 2] & 0xe0) << 3) | (src[s - 1]);
                break;
            }
            case TAG_COPY2: { // tslint:disable-line
                s += 3;
                if (s > slen) {
                    throw new Error(CORRUPT);
                }
                length = 1 + length;
                offset = (src[s - 2]) | ((src[s - 1]) << 8);
                break;
            }
            case TAG_COPY4: { // tslint:disable-line
                s += 5;
                if (s > slen) {
                    throw new Error(CORRUPT);
                }
                length = 1 + length;
                offset = (src[s - 4]) | (src[s - 3] << 8)
                    | (src[s - 2] << 16) | (src[s - 1] << 24);
                break;
            }
        }
        if (offset <= 0 || d < offset || length > dlen - d) {
            throw new Error(CORRUPT);
        }
        for (let end = d + length; d !== end; d++) {
            dst[d] = dst[d - offset];
        }
    }
    if (d !== origLen) {
        throw new Error(CORRUPT);
    }
    return dst.subarray(0, d);
}
