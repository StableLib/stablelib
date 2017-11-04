// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { SerializableHash } from "@stablelib/hash";
import { readUint32LE, writeUint32LE } from "@stablelib/binary";
import { wipe } from "@stablelib/wipe";

export const BLOCK_SIZE = 64;
export const DIGEST_LENGTH = 32;
export const KEY_LENGTH = 32;
export const PERSONALIZATION_LENGTH = 8;
export const SALT_LENGTH = 8;

export const MAX_LEAF_SIZE = Math.pow(2, 32) - 1;
export const MAX_NODE_OFFSET = Math.pow(2, 48) - 1;
export const MAX_FANOUT = 255;
export const MAX_MAX_DEPTH = 255; // not a typo

export type Config = {
    key?: Uint8Array;
    salt?: Uint8Array;
    personalization?: Uint8Array;
    tree?: Tree;
};

export type Tree = {
    fanout: number; // fanout
    maxDepth: number; // maximal depth
    leafSize: number; // leaf maximal byte length (0 for unlimited)
    nodeOffset: number; // node offset (0 for first, leftmost or leaf), max 2⁴⁸-1
    nodeDepth: number; // node depth (0 for leaves)
    innerDigestLength: number; // inner digest length
    lastNode: boolean; // indicates processing of the last node of layer
};

// TODO(dchest): these can probably be statically checked in TS 2.1.

// Config and Tree objects are also checked in runtime
// to make sure they contain only allowed keys.
const ALLOWED_CONFIG_KEYS = ["key", "salt", "personalization", "tree"];

const ALLOWED_TREE_KEYS = [
    "fanout", "maxDepth", "leafSize", "nodeOffset",
    "nodeDepth", "innerDigestLength", "lastNode"
];


const IV = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

export class BLAKE2s implements SerializableHash {
    readonly blockSize = BLOCK_SIZE;

    private _state = new Uint32Array(IV); // hash state, initialized with IV
    private _buffer = new Uint8Array(BLOCK_SIZE); // buffer for data
    private _bufferLength = 0; // number of bytes in buffer
    private _ctr0 = 0; // low bits of byte counter
    private _ctr1 = 0; // high bits of byte counter
    private _flag0 = 0;
    private _flag1 = 0;
    private _lastNode = false;
    private _finished = false;

    private _paddedKey: Uint8Array | undefined; // copy of zero-padded key if present
    private _initialState: Uint32Array; // initial state after initialization

    constructor(public digestLength = 32, config?: Config) {
        // Validate digest length.
        if (digestLength < 1 || digestLength > DIGEST_LENGTH) {
            throw new Error("blake2s: wrong digest length");
        }

        // Validate config, if present.
        if (config) {
            this.validateConfig(config);
        }

        // Get key length from config.
        let keyLength = 0;
        if (config && config.key) {
            keyLength = config.key.length;
        }

        // Get tree fanout and maxDepth from config.
        let fanout = 1;
        let maxDepth = 1;
        if (config && config.tree) {
            fanout = config.tree.fanout;
            maxDepth = config.tree.maxDepth;
        }

        // Xor common parameters into state.
        this._state[0] ^= digestLength | (keyLength << 8) | (fanout << 16) | (maxDepth << 24);

        // Xor tree parameters into state.
        if (config && config.tree) {
            this._state[1] ^= config.tree.leafSize;

            const nofHi = config.tree.nodeOffset / 0x100000000 >>> 0;
            const nofLo = config.tree.nodeOffset >>> 0;

            this._state[2] ^= nofLo;
            this._state[3] ^= nofHi | (config.tree.nodeDepth << 16) |
                (config.tree.innerDigestLength << 24);

            this._lastNode = config.tree.lastNode;
        }

        // Xor salt into state.
        if (config && config.salt) {
            this._state[4] ^= readUint32LE(config.salt, 0);
            this._state[5] ^= readUint32LE(config.salt, 4);
        }

        // Xor personalization into state.
        if (config && config.personalization) {
            this._state[6] ^= readUint32LE(config.personalization, 0);
            this._state[7] ^= readUint32LE(config.personalization, 4);
        }

        // Save a copy of initialized state for reset.
        this._initialState = new Uint32Array(this._state);

        // Process key.
        if (config && config.key && keyLength > 0) {
            this._paddedKey = new Uint8Array(BLOCK_SIZE);
            this._paddedKey.set(config.key);

            // Put padded key into buffer.
            this._buffer.set(this._paddedKey);
            this._bufferLength = BLOCK_SIZE;
        }
    }

    reset(): this {
        // Restore initial state.
        this._state.set(this._initialState);

        if (this._paddedKey) {
            // Put padded key into buffer.
            this._buffer.set(this._paddedKey);
            this._bufferLength = BLOCK_SIZE;
        } else {
            this._bufferLength = 0;
        }

        // Clear counters and flags.
        this._ctr0 = 0;
        this._ctr1 = 0;
        this._flag0 = 0;
        this._flag1 = 0;
        this._finished = false;

        return this;
    }

    validateConfig(config: Config) {
        if (config.key && config.key.length > KEY_LENGTH) {
            throw new Error("blake2s: wrong key length");
        }
        if (config.salt && config.salt.length !== SALT_LENGTH) {
            throw new Error("blake2s: wrong salt length");
        }
        if (config.personalization &&
            config.personalization.length !== PERSONALIZATION_LENGTH) {
            throw new Error("blake2s: wrong personalization length");
        }
        if (config.tree) {
            if (config.tree.fanout < 0 || config.tree.fanout > MAX_FANOUT) {
                throw new Error("blake2s: wrong tree fanout");
            }
            if (config.tree.maxDepth < 0 || config.tree.maxDepth > MAX_MAX_DEPTH) {
                throw new Error("blake2s: wrong tree depth");
            }
            if (config.tree.leafSize < 0 || config.tree.leafSize > MAX_LEAF_SIZE) {
                throw new Error("blake2s: wrong leaf size");
            }
            if (config.tree.innerDigestLength < 0 ||
                config.tree.innerDigestLength > DIGEST_LENGTH) {
                throw new Error("blake2s: wrong tree inner digest length");
            }
            if (config.tree.nodeOffset < 0 || config.tree.nodeOffset > MAX_NODE_OFFSET) {
                throw new Error("blake2s: tree node offset is too large");
            }
        }
        // Make sure there are no misspelt keys in config and tree.
        for (let k in config) {
            if (ALLOWED_CONFIG_KEYS.indexOf(k) === -1) {
                throw new Error("blake2s: unexpected key in config: " + k);
            }
        }
        if (config.tree) {
            for (let k in config.tree) {
                if (ALLOWED_TREE_KEYS.indexOf(k) === -1) {
                    throw new Error("blake2s: unexpected key in config.tree: " + k);
                }
            }
        }
    }

    update(data: Uint8Array, dataLength = data.length): this {
        if (this._finished) {
            throw new Error("blake2s: can't update because hash was finished.");
        }

        const left = BLOCK_SIZE - this._bufferLength;
        let dataPos = 0;

        if (dataLength === 0) {
            return this;
        }

        // Finish buffer.
        if (dataLength > left) {
            for (let i = 0; i < left; i++) {
                this._buffer[this._bufferLength + i] = data[dataPos + i];
            }
            this._processBlock(BLOCK_SIZE);
            dataPos += left;
            dataLength -= left;
            this._bufferLength = 0;
        }

        // Process data blocks.
        while (dataLength > BLOCK_SIZE) {
            for (let i = 0; i < BLOCK_SIZE; i++) {
                this._buffer[i] = data[dataPos + i];
            }
            this._processBlock(BLOCK_SIZE);
            dataPos += BLOCK_SIZE;
            dataLength -= BLOCK_SIZE;
            this._bufferLength = 0;
        }

        // Copy leftovers to buffer.
        for (let i = 0; i < dataLength; i++) {
            this._buffer[this._bufferLength + i] = data[dataPos + i];
        }
        this._bufferLength += dataLength;

        return this;
    }

    finish(out: Uint8Array): this {
        if (!this._finished) {
            for (let i = this._bufferLength; i < BLOCK_SIZE; i++) {
                this._buffer[i] = 0;
            }

            // Set last block flag.
            this._flag0 = 0xffffffff;

            // Set last node flag if last node in tree.
            if (this._lastNode) {
                this._flag1 = 0xffffffff;
            }

            this._processBlock(this._bufferLength);
            this._finished = true;
        }
        // Reuse buffer as temporary space for digest.
        const tmp = this._buffer.subarray(0, 32);
        for (let i = 0; i < 8; i++) {
            writeUint32LE(this._state[i], tmp, i * 4);
        }
        out.set(tmp.subarray(0, out.length));
        return this;
    }

    digest(): Uint8Array {
        const out = new Uint8Array(this.digestLength);
        this.finish(out);
        return out;
    }

    clean() {
        wipe(this._state);
        wipe(this._buffer);
        wipe(this._initialState);
        if (this._paddedKey) {
            wipe(this._paddedKey);
        }
        this._bufferLength = 0;
        this._ctr0 = 0;
        this._ctr1 = 0;
        this._flag0 = 0;
        this._flag1 = 0;
        this._lastNode = false;
        this._finished = false;
    }

    saveState(): SavedState {
        if (this._finished) {
            throw new Error("blake2s: cannot save finished state");
        }
        return {
            state: new Uint32Array(this._state),
            buffer: new Uint8Array(this._buffer),
            bufferLength: this._bufferLength,
            ctr0: this._ctr0,
            ctr1: this._ctr1,
            flag0: this._flag0,
            flag1: this._flag1,
            lastNode: this._lastNode,
            paddedKey: this._paddedKey ? new Uint8Array(this._paddedKey) : undefined,
            initialState: new Uint32Array(this._initialState)
        };
    }

    restoreState(savedState: SavedState): this {
        this._state.set(savedState.state);
        this._buffer.set(savedState.buffer);
        this._bufferLength = savedState.bufferLength;
        this._ctr0 = savedState.ctr0;
        this._ctr1 = savedState.ctr1;
        this._flag0 = savedState.flag0;
        this._flag1 = savedState.flag1;
        this._lastNode = savedState.lastNode;
        if (this._paddedKey) {
            wipe(this._paddedKey);
        }
        this._paddedKey = savedState.paddedKey ? new Uint8Array(savedState.paddedKey) : undefined;
        this._initialState.set(savedState.initialState);
        return this;
    }

    cleanSavedState(savedState: SavedState): void {
        wipe(savedState.state);
        wipe(savedState.buffer);
        wipe(savedState.initialState);
        if (savedState.paddedKey) {
            wipe(savedState.paddedKey);
        }
        savedState.bufferLength = 0;
        savedState.ctr0 = 0;
        savedState.ctr1 = 0;
        savedState.flag0 = 0;
        savedState.flag1 = 0;
        savedState.lastNode = false;
    }

    private _processBlock(length: number) {
        let nc = this._ctr0 + length;
        this._ctr0 = nc >>> 0;
        if (nc !== this._ctr0) {
            this._ctr1++;
        }

        let v0 = this._state[0],
            v1 = this._state[1],
            v2 = this._state[2],
            v3 = this._state[3],
            v4 = this._state[4],
            v5 = this._state[5],
            v6 = this._state[6],
            v7 = this._state[7],
            v8 = IV[0],
            v9 = IV[1],
            v10 = IV[2],
            v11 = IV[3],
            v12 = IV[4] ^ this._ctr0,
            v13 = IV[5] ^ this._ctr1,
            v14 = IV[6] ^ this._flag0,
            v15 = IV[7] ^ this._flag1;

        const x = this._buffer;
        const m0 = (x[3] << 24) | (x[2] << 16) | (x[1] << 8) | x[0];
        const m1 = (x[7] << 24) | (x[6] << 16) | (x[5] << 8) | x[4];
        const m2 = (x[11] << 24) | (x[10] << 16) | (x[9] << 8) | x[8];
        const m3 = (x[15] << 24) | (x[14] << 16) | (x[13] << 8) | x[12];
        const m4 = (x[19] << 24) | (x[18] << 16) | (x[17] << 8) | x[16];
        const m5 = (x[23] << 24) | (x[22] << 16) | (x[21] << 8) | x[20];
        const m6 = (x[27] << 24) | (x[26] << 16) | (x[25] << 8) | x[24];
        const m7 = (x[31] << 24) | (x[30] << 16) | (x[29] << 8) | x[28];
        const m8 = (x[35] << 24) | (x[34] << 16) | (x[33] << 8) | x[32];
        const m9 = (x[39] << 24) | (x[38] << 16) | (x[37] << 8) | x[36];
        const m10 = (x[43] << 24) | (x[42] << 16) | (x[41] << 8) | x[40];
        const m11 = (x[47] << 24) | (x[46] << 16) | (x[45] << 8) | x[44];
        const m12 = (x[51] << 24) | (x[50] << 16) | (x[49] << 8) | x[48];
        const m13 = (x[55] << 24) | (x[54] << 16) | (x[53] << 8) | x[52];
        const m14 = (x[59] << 24) | (x[58] << 16) | (x[57] << 8) | x[56];
        const m15 = (x[63] << 24) | (x[62] << 16) | (x[61] << 8) | x[60];

        // Round 1.
        v0 = v0 + m0 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m2 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m4 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m6 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m5 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m7 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m3 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m1 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m8 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m10 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m12 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m14 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m13 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m15 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m11 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m9 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 2.
        v0 = v0 + m14 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m4 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m9 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m13 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m15 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m6 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m8 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m10 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m1 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m0 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m11 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m5 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m7 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m3 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m2 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m12 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 3.
        v0 = v0 + m11 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m12 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m5 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m15 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m2 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m13 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m0 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m8 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m10 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m3 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m7 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m9 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m1 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m4 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m6 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m14 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 4.
        v0 = v0 + m7 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m3 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m13 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m11 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m12 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m14 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m1 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m9 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m2 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m5 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m4 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m15 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m0 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m8 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m10 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m6 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 5.
        v0 = v0 + m9 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m5 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m2 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m10 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m4 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m15 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m7 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m0 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m14 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m11 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m6 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m3 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m8 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m13 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m12 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m1 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 6.
        v0 = v0 + m2 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m6 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m0 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m8 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m11 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m3 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m10 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m12 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m4 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m7 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m15 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m1 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m14 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m9 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m5 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m13 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 7.
        v0 = v0 + m12 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m1 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m14 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m4 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m13 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m10 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m15 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m5 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m0 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m6 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m9 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m8 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m2 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m11 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m3 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m7 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 8.
        v0 = v0 + m13 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m7 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m12 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m3 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m1 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m9 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m14 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m11 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m5 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m15 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m8 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m2 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m6 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m10 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m4 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m0 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 9.
        v0 = v0 + m6 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m14 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m11 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m0 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m3 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m8 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m9 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m15 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m12 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m13 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m1 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m10 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m4 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m5 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m7 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m2 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 10.
        v0 = v0 + m10 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m8 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m7 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m1 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m6 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m5 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m4 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m2 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m15 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m9 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m3 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m13 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m12 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m0 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m14 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m11 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        this._state[0] ^= v0 ^ v8;
        this._state[1] ^= v1 ^ v9;
        this._state[2] ^= v2 ^ v10;
        this._state[3] ^= v3 ^ v11;
        this._state[4] ^= v4 ^ v12;
        this._state[5] ^= v5 ^ v13;
        this._state[6] ^= v6 ^ v14;
        this._state[7] ^= v7 ^ v15;
    }

}

export type SavedState = {
    state: Uint32Array;
    buffer: Uint8Array;
    bufferLength: number;
    ctr0: number;
    ctr1: number;
    flag0: number;
    flag1: number;
    lastNode: boolean;
    paddedKey: Uint8Array | undefined;
    initialState: Uint32Array;
};

export function hash(data: Uint8Array, digestLength = DIGEST_LENGTH, config?: Config): Uint8Array {
    const h = new BLAKE2s(digestLength, config);
    h.update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}
