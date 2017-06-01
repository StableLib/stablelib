// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

const INVALID_UTF16 = "utf8: invalid string";
const INVALID_UTF8 = "utf8: invalid source encoding";

export function encode(s: string): Uint8Array {
    // Calculate result length and allocate output array.
    // encodedLength() also validates string and throws errors,
    // so we don't need repeat validation here.
    const arr = new Uint8Array(encodedLength(s));

    let pos = 0;
    for (let i = 0; i < s.length; i++) {
        let c = s.charCodeAt(i);
        if (c < 0x80) {
            arr[pos++] = c;
        } else if (c < 0x800) {
            arr[pos++] = 0xc0 | c >> 6;
            arr[pos++] = 0x80 | c & 0x3f;
        } else if (c < 0xd800) {
            arr[pos++] = 0xe0 | c >> 12;
            arr[pos++] = 0x80 | (c >> 6) & 0x3f;
            arr[pos++] = 0x80 | c & 0x3f;
        } else {
            i++; // get one more character
            c = (c & 0x3ff) << 10;
            c |= s.charCodeAt(i) & 0x3ff;
            c += 0x10000;

            arr[pos++] = 0xf0 | c >> 18;
            arr[pos++] = 0x80 | (c >> 12) & 0x3f;
            arr[pos++] = 0x80 | (c >> 6) & 0x3f;
            arr[pos++] = 0x80 | c & 0x3f;
        }
    }
    return arr;
}

export function encodedLength(s: string): number {
    let result = 0;
    for (let i = 0; i < s.length; ++i) {
        const c = s.charCodeAt(i);
        if (c < 0x80) {
            result += 1;
        } else if (c < 0x800) {
            result += 2;
        } else if (c < 0xd800) {
            result += 3;
        } else if (c <= 0xdfff) {
            if (i >= s.length - 1) {
                throw new Error(INVALID_UTF16);
            }
            i++; // "eat" next character
            result += 4;
        } else {
            throw new Error(INVALID_UTF16);
        }
    }
    return result;
}


export function decode(arr: Uint8Array): string {
    const chars: number[] = [];
    let pos = 0;
    while (pos < arr.length) {
        let b = arr[pos++];
        if (b & 0x80) {
            if (b < 0xe0) {
                // Need 1 more byte.
                if (pos >= arr.length) {
                    throw new Error(INVALID_UTF8);
                }
                const n1 = arr[pos++];
                b = (b & 0x1f) << 6 | (n1 & 0x3f);
            } else if (b < 0xf0) {
                // Need 2 more bytes.
                if (pos >= arr.length - 1) {
                    throw new Error(INVALID_UTF8);
                }
                const n1 = arr[pos++];
                const n2 = arr[pos++];
                b = (b & 0x0f) << 12 | (n1 & 0x3f) << 6 | (n2 & 0x3f);
            } else {
                // Need 3 more bytes.
                if (pos >= arr.length - 2) {
                    throw new Error(INVALID_UTF8);
                }
                const n1 = arr[pos++];
                const n2 = arr[pos++];
                const n3 = arr[pos++];
                b = (b & 0x0f) << 18 | (n1 & 0x3f) << 12 | (n2 & 0x3f) << 6 | (n3 & 0x3f);
            }
        }

        if (b < 0x10000) {
            if (b >= 0xd800 && b <= 0xdfff) {
                throw new Error(INVALID_UTF8);
            }
            chars.push(b);
        } else {
            // Surrogate pair.
            b -= 0x10000;
            chars.push(0xd800 | (b >> 10));
            chars.push(0xdc00 | (b & 0x3ff));
        }
    }
    return String.fromCharCode.apply(null, chars);
}
