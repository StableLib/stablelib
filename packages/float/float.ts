// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package float provides helper functions for floating-point numbers.
 */

interface ObjectWithIs extends Object {
    is?: (a: any, b: any) => boolean;
}

/**
 * Returns true if the argument is -0, false otherwise.
 */
export const isNegativeZero =
    typeof (Object as ObjectWithIs).is !== "undefined"
        ? (x: number) => (Object as ObjectWithIs).is!(x, -0)
        : (x: number) => x === 0 && (1 / x < 0);


const froundShim = (() => {
    const tmp = new Float32Array(1);
    return (x: number) => {
        tmp[0] = +x;
        return tmp[0];
    };
})();

/**
 * Returns new number rounded to float32.
 *
 *  In ES2015, Math.fround.
 */
export const fround = ((Math as { fround?: (x: number) => number })).fround || froundShim;


function log2Shim(x: number) {
    return Math.log(x) * Math.LOG2E;
}

/**
 * Returns base 2 logarithm.
 *
 * Note that result approximation is implementation-dependent.
 * If result is to be used in bit masks, use Math.round() on it.
 *
 * In ES2015, Math.log2.
 */
export const log2 = ((Math as { log2?: (x: number) => number})).log2 || log2Shim;

