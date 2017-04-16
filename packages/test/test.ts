// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Wrapper for Jasmine async tests.
 *
 * Example:
 *
 *      describe("Something", () => {
 *          it("should do something", asyncTest(async () => {
 *              expect(await something()).toBeTrue();
 *          }));
 *      });
 *
 */
export const asyncTest = (fn: () => any) => (done: any) => fn().then(done, done.fail);
