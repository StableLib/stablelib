// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { ByteWriter } from "./bytewriter";

describe("ByteWriter", () => {
    it("should write bytes", () => {
        const w = new ByteWriter();
        w.write(new Uint8Array([1, 2, 3]));
        w.write(new Uint8Array([4, 5]));
        w.writeByte(6);
        w.write(new Uint8Array([7, 8, 9]));
        const result = w.finish();
        const good = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
        expect(result).toEqual(good);
    });

    it("should write many", () => {
       const w = new ByteWriter();
       w.writeMany([
           new Uint8Array([1, 2, 3, 4]),
           new Uint8Array([5, 6, 7]),
           new Uint8Array(0),
           new Uint8Array([8]),
           new Uint8Array([9, 0])
       ]);
       w.writeByte(255);
       const result = w.finish();
       const good = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 255]);
       expect(result).toEqual(good);
    });

    it("should write uint32", () => {
       const w = new ByteWriter();
       w.writeByte(1);
       w.writeUint32BE(4294901660);
       w.writeByte(233);
       const result = w.finish();
       const good = new Uint8Array([1, 255, 254, 255, 156, 233]);
       expect(result).toEqual(good);
    });

    // TODO(dchest): test for writeXXX.
});
