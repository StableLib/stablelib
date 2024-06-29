// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package float provides helper functions for floating-point numbers.
 */

/**
 * Returns true if the argument is -0, false otherwise.
 */
export const isNegativeZero = (x: number) => Object.is(x, -0)

/**
 * Returns new number rounded to float32.
 */
export const fround = Math.fround;

/**
 * Returns base 2 logarithm.
 *
 * Note that result approximation is implementation-dependent.
 * If result is to be used in bit masks, use Math.round() on it.
 */
export const log2 = Math.log2;

