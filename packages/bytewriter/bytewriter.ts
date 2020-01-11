// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package bytewriter implements byte array writer.
 */

import { wipe } from "@stablelib/wipe";
import { isSafeInteger } from "@stablelib/int";
import {
    writeUint64BE, writeUint64LE,
    writeUintBE, writeUintLE
} from "@stablelib/binary";

/** Preallocated empty array */
const MIN_CAPACITY = 8;

/**
 * ByteWriter is a convenient way to combine bytes into Uint8Array.
 */
export class ByteWriter {
    private _prev: Uint8Array[] = []; // previous byte arrays
    private _arr: Uint8Array; // current byte array
    private _pos = 0; // position in _arr
    private _len = 0; // total length
    private _view: DataView; // view into current byte array, created on-demand

    private _finished = false;

    /**
     * Creates a new ByteWriter with the optional initial capacity.
     */
    constructor(initialCapacity = MIN_CAPACITY) {
        this._arr = new Uint8Array(initialCapacity);
        this._view = new DataView(this._arr.buffer);
    }

    /**
     * Returns the current total length of byte array.
     */
    get length(): number {
        return this._len;
    }

    // Returns the position to write to.
    private _resize(add: number): number {
        let newLen = this._len + add;
        if (!isSafeInteger(newLen)) {
            throw new Error("ByteWriter: result is too large");
        }

        let newPos = this._pos + add;
        if (newPos < this._arr.length) {
            // No resizing needed, record new length and position.
            this._len = newLen;
            const oldPos = this._pos;
            this._pos = newPos;
            return oldPos;
        }

        // Not enough space for new addition.
        // Remember this byte array and create a new one.
        this._prev.push(this._arr.subarray(0, this._pos));

        // Allocate new byte array double the size of the previous one.
        let newCap = Math.max(this._arr.length * 2, MIN_CAPACITY);
        // If it's not enough, just allocate as asked.
        if (newCap < add) {
            newCap = add;
        }
        this._arr = new Uint8Array(newCap);
        this._view = new DataView(this._arr.buffer);
        this._pos = add;
        this._len = newLen;
        return 0;
    }

    // Makes sure buffer can accept len bytes by expanding it if needed.
    // Returns position to write to.
    private _ensureSpace(add: number): number {
        if (this._finished) {
            throw new Error("ByteWriter: writing to finished writer");
        }
        return this._resize(add);
    }

    /**
     * Resets position.
     */
    reset(): this {
        // _arr and _view stay the same, everything else is reset.
        wipe(this._arr);
        this._prev = [];
        this._len = 0;
        this._pos = 0;
        this._finished = false;
        return this;
    }

    /**
     * Returns the resulting byte array.
     */
    finish(): Uint8Array {
        if (this._finished) {
            throw new Error("ByteWriter is already finished");
        }
        this._finished = true;

        // Push the current array.
        this._prev.push(this._arr.subarray(0, this._pos));

        // Concatenate all arrays.
        const result = new Uint8Array(this._len);
        let offset = 0;
        for (let i = 0; i < this._prev.length; i++) {
            const arr = this._prev[i];
            result.set(arr, offset);
            offset += arr.length;
        }

        return result;
    }

    clean(): void {
        this._prev.forEach(arr => wipe(arr));
        this.reset();
    }

    write(arr: Uint8Array): this {
        const pos = this._ensureSpace(arr.length);
        this._arr.set(arr, pos);
        return this;
    }

    writeMany(arrays: Uint8Array[]): this {
        arrays.forEach(item => this.write(item));
        return this;
    }

    writeByte(byte: number): this {
        const pos = this._ensureSpace(1);
        this._arr[pos] = byte;
        return this;
    }

    writeUint8 = this.writeByte;

    writeUint16BE(value: number): this {
        const pos = this._ensureSpace(2);
        this._view.setUint16(pos, value, false);
        return this;
    }

    writeInt16BE(value: number): this {
        const pos = this._ensureSpace(2);
        this._view.setInt16(pos, value, false);
        return this;
    }

    writeUint16LE(value: number): this {
        const pos = this._ensureSpace(2);
        this._view.setUint16(pos, value, true);
        return this;
    }

    writeInt16LE(value: number): this {
        const pos = this._ensureSpace(2);
        this._view.setInt16(pos, value, true);
        return this;
    }

    writeUint32BE(value: number): this {
        const pos = this._ensureSpace(4);
        this._view.setUint32(pos, value, false);
        return this;
    }

    writeInt32BE(value: number): this {
        const pos = this._ensureSpace(4);
        this._view.setInt32(pos, value, false);
        return this;
    }

    writeUint32LE(value: number): this {
        const pos = this._ensureSpace(4);
        this._view.setUint32(pos, value, true);
        return this;
    }

    writeInt32LE(value: number): this {
        const pos = this._ensureSpace(4);
        this._view.setInt32(pos, value, true);
        return this;
    }

    writeUint64BE(value: number): this {
        const pos = this._ensureSpace(8);
        writeUint64BE(value, this._arr, pos);
        return this;
    }

    writeInt64BE = this.writeUint64BE;

    writeUint64LE(value: number): this {
        const pos = this._ensureSpace(8);
        writeUint64LE(value, this._arr, pos);
        return this;
    }

    writeInt64LE = this.writeUint64LE;

    writeUintLE(bitLength: number, value: number): this {
        const pos = this._ensureSpace(bitLength / 8);
        writeUintLE(bitLength, value, this._arr, pos);
        return this;
    }

    writeUintBE(bitLength: number, value: number): this {
        const pos = this._ensureSpace(bitLength / 8);
        writeUintBE(bitLength, value, this._arr, pos);
        return this;
    }

    writeFloat32BE(value: number): this {
        const pos = this._ensureSpace(4);
        this._view.setFloat32(pos, value, false);
        return this;
    }

    writeFloat32LE(value: number): this {
        const pos = this._ensureSpace(4);
        this._view.setFloat32(pos, value, true);
        return this;
    }

    writeFloat64BE(value: number): this {
        const pos = this._ensureSpace(8);
        this._view.setFloat64(pos, value, false);
        return this;
    }

    writeFloat64LE(value: number): this {
        const pos = this._ensureSpace(8);
        this._view.setFloat64(pos, value, true);
        return this;
    }
}
