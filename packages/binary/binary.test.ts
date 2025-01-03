// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { describe, expect, it } from 'vitest';
import {
    readInt16BE, readInt16LE, readInt32BE, readInt32LE,
    readInt64BE, readInt64LE,
    readUint16BE, writeUint16BE, readUint16LE, writeUint16LE,
    readUint32BE, writeUint32BE, readUint32LE, writeUint32LE,
    readUint64BE, writeUint64BE, readUint64LE, writeUint64LE,
    readUintLE, writeUintLE, readUintBE, writeUintBE,
    readFloat32BE, writeFloat32BE, readFloat64BE, writeFloat64BE,
    readFloat32LE, writeFloat32LE, readFloat64LE, writeFloat64LE
} from "./binary.js";

const int16BEVectors: [number, number[]][] = [
    [0, [0, 0]],
    [1, [0, 1]],
    [255, [0, 255]],
    [-2, [255, 254]],
    [-1, [255, 255]],
    [32767, [127, 255]]
];

const int16LEVectors = int16BEVectors.map(v =>
    [v[0], (v[1] as number[]).slice().reverse()]
) as [number, number[]][];

describe("readInt16BE", () => {
    it("should read correct value", () => {
        int16BEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readInt16BE(buf)).toEqual(v[0]);
        });
    });
});

describe("readInt16LE", () => {
    it("should read correct value", () => {
        int16LEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readInt16LE(buf)).toEqual(v[0]);
        });
    });
});

const uint16BEVectors: [number, number[]][] = [
    [0, [0, 0]],
    [1, [0, 1]],
    [255, [0, 255]],
    [256, [1, 0]],
    [65535, [255, 255]]
];

const uint16LEVectors = uint16BEVectors.map(v =>
    [v[0], (v[1] as number[]).slice().reverse()]
) as [number, number[]][];

describe("readUint16BE", () => {
    it("should read correct value", () => {
        uint16BEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readUint16BE(buf)).toEqual(v[0]);
        });
    });

    it("should read from correct offset", () => {
        const orig = new Uint8Array([0, 1, 2]);
        const value = readUint16BE(orig, 1);
        expect(value).toBe(258);
    });
});

describe("writeUint16BE", () => {
    it("should write correct value", () => {
        uint16BEVectors.forEach(v => {
            const buf = new Uint8Array(2);
            const good = new Uint8Array(v[1] as number[]);
            const value = v[0] as number;
            expect(writeUint16BE(value, buf)).toEqual(good);
        });
    });

    it("should allocate new array if not given", () => {
        expect(Object.prototype.toString.call(writeUint16BE(1))).toBe("[object Uint8Array]");
    });

    it("should write to correct offset", () => {
        const orig = new Uint8Array([0, 1, 2]);
        const result = writeUint16BE(258, new Uint8Array(3), 1);
        expect(result).toEqual(orig);
    });
});

describe("readUint16LE", () => {
    it("should read correct value", () => {
        uint16LEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readUint16LE(buf)).toEqual(v[0]);
        });
    });

    it("should read from correct offset", () => {
        const orig = new Uint8Array([0, 1, 2]);
        const value = readUint16LE(orig, 1);
        expect(value).toBe(513);
    });
});

describe("writeUint16LE", () => {
    it("should write correct value", () => {
        uint16LEVectors.forEach(v => {
            const buf = new Uint8Array(2);
            const good = new Uint8Array(v[1] as number[]);
            const value = v[0] as number;
            expect(writeUint16LE(value, buf)).toEqual(good);
        });
    });

    it("should allocate new array if not given", () => {
        expect(Object.prototype.toString.call(writeUint16LE(1))).toBe("[object Uint8Array]");
    });

    it("should write to correct offset", () => {
        const orig = new Uint8Array([0, 1, 2]);
        const result = writeUint16LE(513, new Uint8Array(3), 1);
        expect(result).toEqual(orig);
    });
});

const int32BEVectors: [number, number[]][] = [
    [0, [0, 0, 0, 0]],
    [1, [0, 0, 0, 1]],
    [255, [0, 0, 0, 255]],
    [-2, [255, 255, 255, 254]],
    [-1, [255, 255, 255, 255]],
    [32767, [0, 0, 127, 255]],
    [2147483647, [127, 255, 255, 255]],
    [-2147483647, [128, 0, 0, 1]]
];

const int32LEVectors = int32BEVectors.map(v =>
    [v[0], (v[1] as number[]).slice().reverse()]
) as [number, number[]][];

describe("readInt32BE", () => {
    it("should read correct value", () => {
        int32BEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readInt32BE(buf)).toEqual(v[0]);
        });
    });
});

describe("readInt32LE", () => {
    it("should read correct value", () => {
        int32LEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readInt32LE(buf)).toEqual(v[0]);
        });
    });
});

const uint32BEVectors: [number, number[]][] = [
    [0, [0, 0, 0, 0]],
    [1, [0, 0, 0, 1]],
    [255, [0, 0, 0, 255]],
    [256, [0, 0, 1, 0]],
    [65535, [0, 0, 255, 255]],
    [16777215, [0, 255, 255, 255]],
    [2147483647, [127, 255, 255, 255]],
    [4294901660, [255, 254, 255, 156]],
    [4294967295, [255, 255, 255, 255]],
];

const uint32LEVectors = uint32BEVectors.map(v =>
    [v[0], (v[1] as number[]).slice().reverse()]
) as [number, number[]][];

describe("readUint32BE", () => {
    it("should read correct value", () => {
        uint32BEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readUint32BE(buf)).toEqual(v[0]);
        });
    });

    it("should read from correct offset", () => {
        const orig = new Uint8Array([0, 1, 2, 3, 4]);
        const value = readUint32BE(orig, 1);
        expect(value).toBe(16909060);
    });
});

describe("writeUint32BE", () => {
    it("should write correct value", () => {
        uint32BEVectors.forEach(v => {
            const buf = new Uint8Array(4);
            const good = new Uint8Array(v[1] as number[]);
            const value = v[0] as number;
            expect(writeUint32BE(value, buf)).toEqual(good);
        });
    });

    it("should allocate new array if not given", () => {
        expect(Object.prototype.toString.call(writeUint32BE(1))).toBe("[object Uint8Array]");
    });

    it("should write to correct offset", () => {
        const orig = new Uint8Array([0, 1, 2, 3, 4]);
        const result = writeUint32BE(16909060, new Uint8Array(5), 1);
        expect(result).toEqual(orig);
    });
});

describe("readUint32LE", () => {
    it("should read correct value", () => {
        uint32LEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readUint32LE(buf)).toEqual(v[0]);
        });
    });

    it("should read from correct offset", () => {
        const orig = new Uint8Array([0, 1, 2, 3, 4]);
        const value = readUint32LE(orig, 1);
        expect(value).toBe(67305985);
    });
});

describe("writeUint32LE", () => {
    it("should write correct value", () => {
        uint32LEVectors.forEach(v => {
            const buf = new Uint8Array(4);
            const good = new Uint8Array(v[1] as number[]);
            const value = v[0] as number;
            expect(writeUint32LE(value, buf)).toEqual(good);
        });
    });

    it("should allocate new array if not given", () => {
        expect(Object.prototype.toString.call(writeUint32LE(1))).toBe("[object Uint8Array]");
    });

    it("should write to correct offset", () => {
        const orig = new Uint8Array([0, 1, 2, 3, 4]);
        const result = writeUint32LE(67305985, new Uint8Array(5), 1);
        expect(result).toEqual(orig);
    });
});

const int64BEVectors: [number, number[]][] = [
    [0, [0, 0, 0, 0, 0, 0, 0, 0]],
    [1, [0, 0, 0, 0, 0, 0, 0, 1]],
    [255, [0, 0, 0, 0, 0, 0, 0, 255]],
    [256, [0, 0, 0, 0, 0, 0, 1, 0]],
    [65535, [0, 0, 0, 0, 0, 0, 255, 255]],
    [16777215, [0, 0, 0, 0, 0, 255, 255, 255]],
    [2147483647, [0, 0, 0, 0, 127, 255, 255, 255]],
    [4294901660, [0, 0, 0, 0, 255, 254, 255, 156]],
    [4294967295, [0, 0, 0, 0, 255, 255, 255, 255]],
    [2146252406, [0, 0, 0, 0, 127, 237, 54, 118]],
    [2147483648, [0, 0, 0, 0, 128, 0, 0, 0]],
    [4294967296, [0, 0, 0, 1, 0, 0, 0, 0]],
    [4295450643, [0, 0, 0, 1, 0, 7, 96, 19]],
    [8589934592, [0, 0, 0, 2, 0, 0, 0, 0]],
    [35184372088610, [0, 0, 31, 255, 255, 255, 255, 34]],
    [-35184372088610, [255, 255, 224, 0, 0, 0, 0, 222]],
    [140737488355326, [0, 0, 127, 255, 255, 255, 255, 254]],
    [9007199254740991, [0, 31, 255, 255, 255, 255, 255, 255]]
];

const int64LEVectors = int64BEVectors.map(v =>
    [v[0], (v[1] as number[]).slice().reverse()]
) as [number, number[]][];

describe("readInt64BE", () => {
    it("should read correct value", () => {
        int64BEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readInt64BE(buf)).toEqual(v[0]);
        });
    });
});

describe("readInt64LE", () => {
    it("should read correct value", () => {
        int64LEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readInt64LE(buf)).toEqual(v[0]);
        });
    });
});

const uint64BEVectors: [number, number[]][] = [
    [0, [0, 0, 0, 0, 0, 0, 0, 0]],
    [1, [0, 0, 0, 0, 0, 0, 0, 1]],
    [255, [0, 0, 0, 0, 0, 0, 0, 255]],
    [256, [0, 0, 0, 0, 0, 0, 1, 0]],
    [65535, [0, 0, 0, 0, 0, 0, 255, 255]],
    [16777215, [0, 0, 0, 0, 0, 255, 255, 255]],
    [2147483647, [0, 0, 0, 0, 127, 255, 255, 255]],
    [4294901660, [0, 0, 0, 0, 255, 254, 255, 156]],
    [4294967295, [0, 0, 0, 0, 255, 255, 255, 255]],
    [2146252406, [0, 0, 0, 0, 127, 237, 54, 118]],
    [2147483648, [0, 0, 0, 0, 128, 0, 0, 0]],
    [4294967296, [0, 0, 0, 1, 0, 0, 0, 0]],
    [4295450643, [0, 0, 0, 1, 0, 7, 96, 19]],
    [8589934592, [0, 0, 0, 2, 0, 0, 0, 0]],
    [35184372088610, [0, 0, 31, 255, 255, 255, 255, 34]],
    [281474976710655, [0, 0, 255, 255, 255, 255, 255, 255]],
    [140737488355326, [0, 0, 127, 255, 255, 255, 255, 254]],
    [9007199254740991, [0, 31, 255, 255, 255, 255, 255, 255]]
];

const uint64LEVectors = uint64BEVectors.map(v =>
    [v[0], (v[1] as number[]).slice().reverse()]
) as [number, number[]][];

describe("readUint64BE", () => {
    it("should read correct value", () => {
        uint64BEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readUint64BE(buf)).toEqual(v[0]);
        });
    });

    it("should read from correct offset", () => {
        const orig = new Uint8Array([0, 0, 1, 2, 3, 4, 5, 6, 7]);
        const value = readUint64BE(orig, 1);
        expect(value).toBe(283686952306183);
    });
});

describe("writeUint64BE", () => {
    it("should write correct value", () => {
        uint64BEVectors.forEach(v => {
            const buf = new Uint8Array(8);
            const good = new Uint8Array(v[1] as number[]);
            const value = v[0] as number;
            expect(writeUint64BE(value, buf)).toEqual(good);
        });
    });

    it("should allocate new array if not given", () => {
        expect(Object.prototype.toString.call(writeUint32BE(1))).toBe("[object Uint8Array]");
    });

    it("should write to correct offset", () => {
        const orig = new Uint8Array([0, 0, 1, 2, 3, 4, 5, 6, 7]);
        const result = writeUint64BE(283686952306183, new Uint8Array(9), 1);
        expect(result).toEqual(orig);
    });
});

describe("readUint64LE", () => {
    it("should read correct value", () => {
        uint64LEVectors.forEach(v => {
            const buf = new Uint8Array(v[1] as number[]);
            expect(readUint64LE(buf)).toEqual(v[0]);
        });
    });

    it("should read from correct offset", () => {
        const orig = new Uint8Array([0, 7, 6, 5, 4, 3, 2, 1, 0]);
        const value = readUint64LE(orig, 1);
        expect(value).toBe(283686952306183);
    });
});

describe("writeUint64LE", () => {
    it("should write correct value", () => {
        uint64LEVectors.forEach(v => {
            const buf = new Uint8Array(8);
            const good = new Uint8Array(v[1] as number[]);
            const value = v[0] as number;
            expect(writeUint64LE(value, buf)).toEqual(good);
        });
    });

    it("should allocate new array if not given", () => {
        expect(Object.prototype.toString.call(writeUint32LE(1))).toBe("[object Uint8Array]");
    });

    it("should write to correct offset", () => {
        const orig = new Uint8Array([0, 7, 6, 5, 4, 3, 2, 1, 0]);
        const result = writeUint64LE(283686952306183, new Uint8Array(9), 1);
        expect(result).toEqual(orig);
    });
});

describe("readUintLE/writeUintLE", () => {
    it("should write and read back 32-bit value", () => {
        const orig = 1234567891;
        const offset = 2;
        const wrote = writeUintLE(32, orig, new Uint8Array(6), offset);
        expect(wrote).toEqual(writeUint32LE(orig, new Uint8Array(6), offset));
        expect(readUint32LE(wrote, offset)).toBe(orig);
        const read = readUintLE(32, wrote, offset);
        expect(read).toBe(orig);
    });

    it("should write and read back 48-bit value", () => {
        const orig = Math.pow(2, 48) - 3;
        const offset = 2;
        const wrote = writeUintLE(48, orig, new Uint8Array(8), offset);
        const read = readUintLE(48, wrote, offset);
        expect(read).toBe(orig);
    });

    it("write throws if given non-integer numbers", () => {
        expect(() => writeUintLE(56, Math.pow(2, 54)))
            .toThrowError("writeUintLE value must be an integer");
    });
});

describe("readUintBE/writeUintBE", () => {
    it("should write and read back 32-bit value", () => {
        const orig = 1234567891;
        const offset = 2;
        const wrote = writeUintBE(32, orig, new Uint8Array(6), offset);
        expect(wrote).toEqual(writeUint32BE(orig, new Uint8Array(6), offset));
        expect(readUint32BE(wrote, offset)).toBe(orig);
        const read = readUintBE(32, wrote, offset);
        expect(read).toBe(orig);
    });

    it("should write and read back 48-bit value", () => {
        const orig = Math.pow(2, 48) - 3;
        const offset = 2;
        const wrote = writeUintBE(48, orig, new Uint8Array(8), offset);
        const read = readUintBE(48, wrote, offset);
        expect(read).toBe(orig);
    });

    it("write throws if given non-integer numbers", () => {
        expect(() => writeUintBE(56, Math.pow(2, 54)))
            .toThrowError("writeUintBE value must be an integer");
    });
});

describe("readFloat32BE/writeFloat32BE", () => {
    it("should write and read back value", () => {
        const orig = 123456.1;
        const wrote = writeFloat32BE(orig);
        expect(wrote.length).toBe(4);
        const read = readFloat32BE(wrote);
        expect(Math.abs(orig - read)).toBeLessThan(0.1);
    });
});

describe("readFloat32LE/writeFloat32LE", () => {
    it("should write and read back value", () => {
        const orig = 123456.1;
        const wrote = writeFloat32LE(orig);
        expect(wrote.length).toBe(4);
        const read = readFloat32LE(wrote);
        expect(Math.abs(orig - read)).toBeLessThan(0.1);
    });
});

describe("readFloat64BE/writeFloat64BE", () => {
    it("should write and read back value", () => {
        const orig = 123456891.123;
        const wrote = writeFloat64BE(orig);
        expect(wrote.length).toBe(8);
        const read = readFloat64BE(wrote);
        expect(read).toBe(orig);
    });
});

describe("readFloat64LE/writeFloat64LE", () => {
    it("should write and read back value", () => {
        const orig = 123456891.123;
        const wrote = writeFloat64LE(orig);
        expect(wrote.length).toBe(8);
        const read = readFloat64LE(wrote);
        expect(read).toBe(orig);
    });
});
