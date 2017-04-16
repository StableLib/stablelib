// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

// Based on snappy-go: https://github.com/golang/snappy
// Copyright 2011 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// https://github.com/golang/snappy/blob/master/LICENSE

// How far back-references can reach.
const MAX_OFFSET = 1 << 15;

// Maximum number of bytes that can be compressed at once.
// See maxCompressedLength() for details.
const MAX_INPUT_SIZE = 1840700241;

const TAG_LITERAL = 0x00;
const TAG_COPY1 = 0x01;
const TAG_COPY2 = 0x02;

/**
 * Returns the maximum length of buffer needed for compression of input of the
 * given length.
 *
 * Returns 0 if the length is too large.
 *
 * Snappy format specifications limits the maximum uncompressed length to
 * 2^32-1, but since JavaScript runtimes can't allocate so much anyway, and
 * Snappy framing format uses no longer than 65536-byte chunks, we limit
 * the maximum compressed size to 2^31-1 = 0x7FFFFFFF, which requires that
 * the maximum uncompressed size is 1840700241 bytes
 * (0x7FFFFFFF ~= 32 + x + x/6).
 *
 * Current JavaScript VMs will still most likely fail to allocate that much, so
 * it is a good idea to limit source length to something smaller.
 */
export function maxCompressedLength(srcLen: number): number {
    if (srcLen < 0 || srcLen > MAX_INPUT_SIZE) {
        return 0;
    }
    return Math.ceil(32 + srcLen + srcLen / 6) | 0;
}

/**
 * Compresses src into dst and returns a subarray into dst containing the
 * compressed data.
 *
 * If no dst is given or if it's smaller than compress bound, it's
 * automatically allocated with the length given by compressBound(src.length).
 *
 * Usually, the length of original (decompressed data) is stored somewhere with
 * compressed data (for example, as 4 little-endian bytes in the beginning), so
 * that an appropriate space can be allocated for decompress(), but this
 * function doesn't do it — it so it's up to the caller to write it.
 *
 * Throws an error if input is too large (see maxCompressedLength()).
 *
 * This is a bare block compression without any framing.
 */
export function compress(src: Uint8Array, dst?: Uint8Array): Uint8Array {
    const slen = src.length;
    const dlen = maxCompressedLength(slen);
    if (dlen === 0) {
        throw new Error("snappy: source is too large");
    }

    if (!dst || dst.length < dlen) {
        dst = new Uint8Array(dlen);
    }

    // Block starts with varint-encoded original length.
    let dpos = writeVarUint(dst, slen);

    // Return early if src is too short.
    if (slen <= 4) {
        if (slen !== 0) {
            dpos = emitLiteral(dst, dpos, src, 0, slen);
        }
        return dst.subarray(0, dpos);
    }

    // Initialize hash table.
    const maxTableSize = 1 << 14;
    let shift = 32 - 8;
    let tableSize = 1 << 8;

    while (tableSize < maxTableSize && tableSize < slen) {
        shift--;
        tableSize *= 2;
    }

    const table = new Int32Array(maxTableSize);

    let s = 0; // iterator position
    let t = 0; // last position with the same hash as s
    let lpos = 0; // start position of any pending literal bytes

    while (s + 3 < slen) {
        // Update the hash table.
        const b0 = src[s];
        const b1 = src[s + 1];
        const b2 = src[s + 2];
        const b3 = src[s + 3];
        const h = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        const hp = (h * 0x1e35a7bd | 0) >>> shift;

        t = table[hp] - 1;
        table[hp] = s + 1;

        // If t is invalid or bytes in source differ from referenced,
        // accumulate a literal byte.
        if (t < 0 || s - t > MAX_OFFSET ||
            b0 !== src[t] ||
            b1 !== src[t + 1] ||
            b2 !== src[t + 2] ||
            b3 !== src[t + 3]) {
            // Skip multiple bytes if the last match was >= 32 bytes prior.
            s += 1 + ((s - lpos) >>> 5);
            continue;
        }

        // Otherwise, we have a match.
        // Emit pending literals.
        if (lpos !== s) {
            dpos = emitLiteral(dst, dpos, src, lpos, s - lpos);
        }
        // Extend match to be as long as possible.
        let s0 = s;
        s = s + 4;
        t = t + 4;
        while (s < slen && src[s] === src[t]) {
            s++;
            t++;
        }
        // Emit the bytes.
        dpos = emitCopy(dst, dpos, s - t, s - s0);
        lpos = s;
    }

    // Emit any final pending literals.
    if (lpos !== slen) {
        dpos = emitLiteral(dst, dpos, src, lpos, slen - lpos);
    }
    return dst.subarray(0, dpos);
}

/**
 * Emits literal and returns the next dpos.
 */
function emitLiteral(dst: Uint8Array, dpos: number, lit: Uint8Array, lpos: number, llen: number): number {
    const n = llen - 1;
    if (n < 60) {
        dst[dpos + 0] = n << 2 | TAG_LITERAL;
        dpos += 1;
    } else if (n < 1 << 8) {
        dst[dpos + 0] = 60 << 2 | TAG_LITERAL;
        dst[dpos + 1] = n;
        dpos += 2;
    } else if (n < 1 << 16) {
        dst[dpos + 0] = 61 << 2 | TAG_LITERAL;
        dst[dpos + 1] = n;
        dst[dpos + 2] = n >> 8;
        dpos += 3;
    } else if (n < 1 << 24) {
        dst[dpos + 0] = 62 << 2 | TAG_LITERAL;
        dst[dpos + 1] = n;
        dst[dpos + 2] = n >> 8;
        dst[dpos + 3] = n >> 16;
        dpos += 4;
    } else {
        dst[dpos + 0] = 63 << 2 | TAG_LITERAL;
        dst[dpos + 1] = n;
        dst[dpos + 2] = n >> 8;
        dst[dpos + 3] = n >> 16;
        dst[dpos + 4] = n >> 24;
        dpos += 5;
    }
    for (let i = 0; i < llen; i++) {
        dst[dpos + i] = lit[lpos + i];
    }
    return dpos + llen;
}

/**
 * Emits copy and returns the next dpos.
 */
function emitCopy(dst: Uint8Array, dpos: number, offset: number, length: number): number {
    while (length >= 68) {
        dst[dpos + 0] = (63 << 2) | TAG_COPY2;
        dst[dpos + 1] = offset;
        dst[dpos + 2] = offset >> 8;
        dpos += 3;
        length -= 64;
    }
    if (length > 64) {
        // Emit a length 60 copy, encoded as 3 bytes.
        dst[dpos + 0] = 59 << 2 | TAG_COPY2;
        dst[dpos + 1] = offset;
        dst[dpos + 2] = offset >> 8;
        dpos += 3;
        length -= 60;
    }
    if (length >= 12 || offset >= 2048) {
        // Emit the remaining copy, encoded as 3 bytes.
        dst[dpos + 0] = ((length - 1) & 0xff) << 2 | TAG_COPY2;
        dst[dpos + 1] = offset;
        dst[dpos + 2] = offset >> 8;
        return dpos + 3;
    }
    // Emit the remaining copy, encoded as 2 bytes.
    dst[dpos + 0] = ((offset >> 8) & 0xff) << 5 | ((length - 4) & 0xff) << 2 | TAG_COPY1;
    dst[dpos + 1] = offset;
    return dpos + 2;
}

/**
 * Write 32-bit unsigned integer as variable integer.
 * Returns the number of bytes written.
 */
function writeVarUint(dst: Uint8Array, x: number): number {
    let i = 0;
    while (x >= 0x80) {
        dst[i] = (x & 0xff) | 0x80;
        x >>>= 7;
        i++;
    }
    dst[i] = x;
    return i + 1;
}
