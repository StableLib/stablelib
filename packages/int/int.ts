// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package int provides helper functions for integerss.
 */

/** 32-bit integer multiplication.  */
export const mul = Math.imul;

/** 32-bit integer addition.  */
export function add(a: number, b: number): number {
    return (a + b) | 0;
}

/**  32-bit integer subtraction.  */
export function sub(a: number, b: number): number {
    return (a - b) | 0;
}

/** 32-bit integer left rotation */
export function rotl(x: number, n: number): number {
    return x << n | x >>> (32 - n);
}

/** 32-bit integer left rotation */
export function rotr(x: number, n: number): number {
    return x << (32 - n) | x >>> n;
}

/**
 * Returns true if the argument is an integer number.
 */
export const isInteger = Number.isInteger;

/**
 *  Math.pow(2, 53) - 1
 */
export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

/**
 * Returns true if the argument is a safe integer number
 * (-MIN_SAFE_INTEGER < number <= MAX_SAFE_INTEGER)
 */
export const isSafeInteger = Number.isSafeInteger;
