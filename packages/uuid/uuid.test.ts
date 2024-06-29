// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { describe, expect, it } from 'vitest';
import { uuid } from "./uuid";

describe("uuid", () => {
    it("should generate UUID", () => {
        expect(uuid()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });

    it("should generate different UUIDs", () => {
        const u1 = uuid();
        const u2 = uuid();
        expect(u1).not.toEqual(u2);
    });
});
