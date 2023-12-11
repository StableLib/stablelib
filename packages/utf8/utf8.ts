// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package utf8 implements UTF-8 encoding and decoding.
 */

const INVALID_UTF16 = "utf8: invalid string";
const INVALID_UTF8 = "utf8: invalid source encoding";

/**
 * Encodes the given string into UTF-8 byte array.
 * Throws if the source string has invalid UTF-16 encoding.
 */
export function encode(s: string): Uint8Array {
    // Calculate result length and allocate output array.
    // encodedLength() validates string and throws errors,
    // so we don't need repeat validation here.
    const arr = new Uint8Array(encodedLength(s));

    let pos = 0;
    for (let i = 0; i < s.length; i++) {
        let c = s.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
            c = ((c - 0xd800) << 10) + (s.charCodeAt(++i) - 0xdc00) + 0x10000;
        }
        if (c < 0x80) {
            arr[pos++] = c;
        } else if (c < 0x800) {
            arr[pos++] = 0xc0 | (c >> 6);
            arr[pos++] = 0x80 | (c & 0x3f);
        } else if (c < 0x10000) {
            arr[pos++] = 0xe0 | (c >> 12);
            arr[pos++] = 0x80 | ((c >> 6) & 0x3f);
            arr[pos++] = 0x80 | (c & 0x3f);
        } else {
            arr[pos++] = 0xf0 | (c >> 18);
            arr[pos++] = 0x80 | ((c >> 12) & 0x3f);
            arr[pos++] = 0x80 | ((c >> 6) & 0x3f);
            arr[pos++] = 0x80 | (c & 0x3f);
        }
    }
    return arr;
}

/**
 * Returns the number of bytes required to encode the given string into UTF-8.
 * Throws if the source string has invalid UTF-16 encoding.
 */
export function encodedLength(s: string): number {
    let result = 0;
    for (let i = 0; i < s.length; i++) {
        let c = s.charCodeAt(i);

        if (c >= 0xd800 && c <= 0xdbff) {
            // surrogate pair
            if (i === s.length - 1) {
                throw new Error(INVALID_UTF16);
            }
            i++;
            const c2 = s.charCodeAt(i);
            if (c2 < 0xdc00 || c2 > 0xdfff) {
                throw new Error(INVALID_UTF16);
            }
            c = ((c - 0xd800) << 10) + (c2 - 0xdc00) + 0x10000;
        }

        if (c < 0x80) {
            result += 1;
        } else if (c < 0x800) {
            result += 2;
        } else if (c < 0x10000) {
            result += 3;
        } else {
            result += 4;
        }
    }
    return result;
}

/**
 * Decodes the given byte array from UTF-8 into a string.
 * Throws if encoding is invalid.
 */
export function decode(arr: Uint8Array): string {
    const chars: string[] = [];
    for (let i = 0; i < arr.length; i++) {
        let b = arr[i];

        if (b & 0x80) {
            let min;
            if (b < 0xe0) {
                // Need 1 more byte.
                if (i >= arr.length) {
                    throw new Error(INVALID_UTF8);
                }
                const n1 = arr[++i];
                if ((n1 & 0xc0) !== 0x80) {
                    throw new Error(INVALID_UTF8);
                }
                b = (b & 0x1f) << 6 | (n1 & 0x3f);
                min = 0x80;
            } else if (b < 0xf0) {
                // Need 2 more bytes.
                if (i >= arr.length - 1) {
                    throw new Error(INVALID_UTF8);
                }
                const n1 = arr[++i];
                const n2 = arr[++i];
                if ((n1 & 0xc0) !== 0x80 || (n2 & 0xc0) !== 0x80) {
                    throw new Error(INVALID_UTF8);
                }
                b = (b & 0x0f) << 12 | (n1 & 0x3f) << 6 | (n2 & 0x3f);
                min = 0x800;
            } else if (b < 0xf8) {
                // Need 3 more bytes.
                if (i >= arr.length - 2) {
                    throw new Error(INVALID_UTF8);
                }
                const n1 = arr[++i];
                const n2 = arr[++i];
                const n3 = arr[++i];
                if ((n1 & 0xc0) !== 0x80 || (n2 & 0xc0) !== 0x80 || (n3 & 0xc0) !== 0x80) {
                    throw new Error(INVALID_UTF8);
                }
                b = (b & 0x0f) << 18 | (n1 & 0x3f) << 12 | (n2 & 0x3f) << 6 | (n3 & 0x3f);
                min = 0x10000;
            } else {
                throw new Error(INVALID_UTF8);
            }

            if (b < min || (b >= 0xd800 && b <= 0xdfff)) {
                throw new Error(INVALID_UTF8);
            }

            if (b >= 0x10000) {
                // Surrogate pair.
                if (b > 0x10ffff) {
                    throw new Error(INVALID_UTF8);
                }
                b -= 0x10000;
                chars.push(String.fromCharCode(0xd800 | (b >> 10)));
                b = 0xdc00 | (b & 0x3ff);
            }
        }

        chars.push(String.fromCharCode(b));
    }
    return chars.join("");
}
