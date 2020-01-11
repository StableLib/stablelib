// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package bytereader implements byte array reader.
 */

import { readUint64BE, readUint64LE, readInt64BE, readInt64LE,
    readUintBE, readUintLE } from "@stablelib/binary";

/**
 * ByteReader reads values from a byte array, keeping track of position.
 */
export class ByteReader {
    private _arr: Uint8Array;
    private _view: DataView; // created on-demand
    private _pos = 0;

    constructor(arr: Uint8Array) {
        this._arr = arr;
        this._view = new DataView(
            this._arr.buffer,
            this._arr.byteOffset,
            this._arr.byteLength
        );
    }

    /**
     * Gets the source length.
     */
    get length(): number {
        return this._arr.length;
    }

    /**
     * Gets the number of unread bytes.
     */
    get unreadLength(): number {
        return this._arr.length - this._pos;
    }

    // Checks if len bytes can be read from buffer.
    // Throws if not.
    private _check(len: number) {
        if (this._pos + len > this._arr.length) {
            throw new Error("ByteReader: read out of bounds");
        }
    }

    // Advances position.
    private _advance(len: number) {
        this._pos += len;
    }

    /**
     * Returns a subarray of internal buffer.
     *
     * It is not recommended it use this function,
     * use read() instead, which will return a copy.
     */
    readNoCopy(length: number): Uint8Array {
        this._check(length);
        const result = this._arr.subarray(this._pos, this._pos + length);
        this._advance(length);
        return result;
    }

    read(length: number): Uint8Array {
        return new Uint8Array(this.readNoCopy(length));
    }

    readByte(): number {
        this._check(1);
        const n = this._arr[this._pos];
        this._advance(1);
        return n;
    }

    readUint8 = this.readByte;

    readInt16BE(): number {
        this._check(2);
        const n = this._view.getInt16(this._pos, false);
        this._advance(2);
        return n;
    }

    readUint16BE(): number {
        this._check(2);
        const n = this._view.getUint16(this._pos, false);
        this._advance(2);
        return n;
    }

    readInt16LE(): number {
        this._check(2);
        const n = this._view.getInt16(this._pos, true);
        this._advance(2);
        return n;
    }

    readUint16LE(): number {
        this._check(2);
        const n = this._view.getUint16(this._pos, true);
        this._advance(2);
        return n;
    }

    readInt32BE(): number {
        this._check(4);
        const n = this._view.getInt32(this._pos, false);
        this._advance(4);
        return n;
    }

    readUint32BE(): number {
        this._check(4);
        const n = this._view.getUint32(this._pos, false);
        this._advance(4);
        return n;
    }

    readInt32LE(): number {
        this._check(4);
        const n = this._view.getInt32(this._pos, true);
        this._advance(4);
        return n;
    }

    readUint32LE(): number {
        this._check(4);
        const n = this._view.getUint32(this._pos, true);
        this._advance(4);
        return n;
    }

    readInt64BE(): number {
        this._check(8);
        const n = readInt64BE(this._arr, this._pos);
        this._advance(8);
        return n;
    }

    readUint64BE(): number {
        this._check(8);
        const n = readUint64BE(this._arr, this._pos);
        this._advance(8);
        return n;
    }

    readInt64LE(): number {
        this._check(8);
        const n = readInt64LE(this._arr, this._pos);
        this._advance(8);
        return n;
    }

    readUint64LE(): number {
        this._check(8);
        const n = readUint64LE(this._arr, this._pos);
        this._advance(8);
        return n;
    }

    readUintBE(bitLength: number): number {
        this._check(bitLength / 8);
        const n = readUintBE(bitLength, this._arr, this._pos);
        this._advance(bitLength / 8);
        return n;
    }

    readUintLE(bitLength: number): number {
        this._check(bitLength / 8);
        const n = readUintLE(bitLength, this._arr, this._pos);
        this._advance(bitLength / 8);
        return n;
    }

    readFloat32BE(): number {
        this._check(4);
        const n = this._view.getFloat32(this._pos, false);
        this._advance(4);
        return n;
    }

    readFloat32LE(): number {
        this._check(4);
        const n = this._view.getFloat32(this._pos, true);
        this._advance(4);
        return n;
    }

    readFloat64BE(): number {
        this._check(8);
        const n = this._view.getFloat64(this._pos, false);
        this._advance(8);
        return n;
    }

    readFloat64LE(): number {
        this._check(8);
        const n = this._view.getFloat64(this._pos, true);
        this._advance(8);
        return n;
    }

    seek(n: number): this {
        if (n < 0) {
            // Seek backward.
            if (this._pos + n < 0) {
                throw new Error("ByteReader: trying to seek out of bounds");
            }
            this._pos += n;
        } else if (n > 0) {
            // Seek forward.
            if (this._pos + n >= this._arr.length) {
                throw new Error("ByteReader: trying to seek out of bounds");
            }
            this._pos += n;
        } else {
            // n == 0, seek to beginning.
            this._pos = 0;
        }
        return this;
    }

}
