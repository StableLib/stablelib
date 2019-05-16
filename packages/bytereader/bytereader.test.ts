// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { ByteReader } from "./bytereader";

describe("ByteReader", () => {
    it("should read bytes", () => {
        const b = new Uint8Array([1, 2, 3, 4, 5]);
        const r = new ByteReader(b);
        expect(r.readByte()).toBe(1);
        expect(r.read(3)).toEqual(new Uint8Array([2, 3, 4]));
        expect(r.readByte()).toEqual(5);
    });

    it("should write uint32", () => {
       const r = new ByteReader(new Uint8Array([1, 255, 254, 255, 156, 133]));
       expect(r.readByte()).toBe(1);
       expect(r.readUint32BE()).toBe(4294901660);
       expect(r.readByte()).toBe(133);
    });

    it("should return the correct number of bytes left", () => {
       const r = new ByteReader(new Uint8Array([1, 2, 3]));
       r.readByte();
       expect(r.unreadLength).toBe(2);
       r.readByte();
       expect(r.unreadLength).toBe(1);
       r.readByte();
       expect(r.unreadLength).toBe(0);
    });

    it("should do correct seek backward", () => {
       const r = new ByteReader(new Uint8Array([1, 2, 3]));

       r.readByte();
       expect(r.unreadLength).toBe(2);

       r.readByte();
       expect(r.unreadLength).toBe(1);

       r.seek(-2);
       expect(r.unreadLength).toBe(3);
    });

    it("should do correct seek forward", () => {
       const r = new ByteReader(new Uint8Array([1, 2, 3]));

       r.seek(2);
       expect(r.unreadLength).toBe(1);
    });

    it("should do correct seek to beginning", () => {
       const r = new ByteReader(new Uint8Array([1, 2, 3]));

       r.readByte();
       expect(r.unreadLength).toBe(2);

       r.readByte();
       expect(r.unreadLength).toBe(1);

       r.seek(0);
       expect(r.unreadLength).toBe(3);
    });

    // TODO(dchest): test for readXXX.

});
