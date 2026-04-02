// Copyright (C) 2016-2026 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package cbor implements CBOR (Concise Binary Object Representation) encoder and decoder.
 */

import * as utf8 from "@stablelib/utf8";
import { ByteWriter } from "@stablelib/bytewriter";
import { ByteReader } from "@stablelib/bytereader";
import { isSafeInteger } from "@stablelib/int";
import { isNegativeZero, fround } from "@stablelib/float";

let decodeUTF8: (data: Uint8Array) => string;
let encodeUTF8: (str: string) => Uint8Array;

if (typeof TextEncoder === "undefined" || typeof TextDecoder === "undefined") {
    decodeUTF8 = utf8.decode;
    encodeUTF8 = utf8.encode;
} else {
    const decoder = new TextDecoder("utf-8", { fatal: true })
    const encoder = new TextEncoder();
    decodeUTF8 = data => decoder.decode(data);
    encodeUTF8 = str => encoder.encode(str);
}

/**
 * CBOR (Concise Binary Object Representation)
 * https://tools.ietf.org/html/rfc7049
 */
const MAX_UINT8 = 255;
const MAX_UINT16 = Math.pow(2, 16) - 1;
const MAX_UINT32 = Math.pow(2, 32) - 1;

// Major types.
const MT_UNSIGNED_INT = 0;
const MT_NEGATIVE_INT = 1;
const MT_BYTE_STRING = 2;
const MT_TEXT_STRING = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_TAG = 6;
const MT_SIMPLE_OR_FLOAT = 7;

// Additional information.
const AI_FALSE = 20;
const AI_TRUE = 21;
const AI_NULL = 22;
const AI_UNDEFINED = 23;

const AI_8_BITS = 24;
const AI_16_BITS = 25;
const AI_32_BITS = 26;
const AI_64_BITS = 27;
const AI_STOP = 31;

const STOP_BYTE = 0xff;

/**
 * Common tags.
 */
export enum Tags {
    DateString = 0,  // automatically decoded to Date
    DateNumber = 1,  // automatically decoded to Date
    PositiveBigNum = 2,
    NegativeBigNum = 3,
    Decimal = 4,
    BigFloat = 5,
    URI = 32,
    Base64URL = 33,
    Base64 = 34,
    RegExp = 35, // automatically decoded to RegExp
    MIMEMessage = 36,
    CBOR = 24,
    CBORSelf = 55799
}

/**
 * Tagged value.
 *
 * Predefined tags are listed in Tags enum.
 *
 * Some tagged values are handled automatically by default (Tags.DateString and
 * Tags.DateNumber correspond to Date object, Tags.RegExp to RegExp). Others
 * are returned as an instance of Tagged, unless encoder/decoder is provided
 * with customer converters. If Tagged is passed to encoder, it will properly
 * encode it.
 *
 * IANA keeps "CBOR Tags" registry (see RFC 7049, Section 7.2).
 */
export class Tagged {
    constructor(public tag: number, public value: any | null | undefined) { }
}

/**
 * Interface describing a custom tagged value converter.
 */
/**
 * Tagged value encoder.
 *
 * If it can encode the object, it must return a Tagged instance,
 * otherwise must return undefined.
 */
export type TaggedEncoder<T> = (obj: T | object) => Tagged | undefined;

/**
 * Tagged value decoder.
 *
 * If it can decode a Tagged value (by checking its tag property),
 * it must return this value, otherwise must return undefined.
 */
export type TaggedDecoder<T> = (tagged: Tagged) => T | undefined;

export const DateStringEncoder: TaggedEncoder<Date> =
    date => {
        if (!(date instanceof Date)) {
            return undefined;
        }
        return new Tagged(Tags.DateString, date.toISOString().slice(0, 19) + "Z");
    };

export const DateStringDecoder: TaggedDecoder<Date> =
    ({ tag, value }) => {
        if (tag !== Tags.DateString) {
            return undefined;
        }
        if (typeof value !== "string") {
            throw new CBORInvalidFormatError(`cbor: unexpected type for date string: "${typeof value}"`);
        }
        if (!ISO_DATE_RX.test(value)) {
            throw new CBORInvalidFormatError(`cbor: invalid date string format`);
        }
        return new Date(value);
    };

// This encoder is unused by default, because dates are processed with
// DateStringEncoder. The decoder is used, though.
export const DateNumberEncoder: TaggedEncoder<Date> =
    date => {
        if (!(date instanceof Date)) {
            return undefined;
        }
        return new Tagged(Tags.DateNumber, date.getTime() / 1000);
    };

export const DateNumberDecoder: TaggedDecoder<Date> =
    ({ tag, value }) => {
        if (tag !== Tags.DateNumber) {
            return undefined;
        }
        if (typeof value !== "number") {
            throw new CBORInvalidFormatError(`cbor: unexpected type for date number: "${typeof value}"`);
        }
        return new Date(value * 1000);
    };

export const RegExpEncoder: TaggedEncoder<RegExp> =
    rx => {
        if (!(rx instanceof RegExp)) {
            return undefined;
        }
        return new Tagged(Tags.RegExp, rx.toString());
    };

export const RegExpDecoder: TaggedDecoder<RegExp> =
    ({ tag, value }) => {
        if (tag !== Tags.RegExp) {
            return undefined;
        }
        if (typeof value !== "string") {
            throw new CBORInvalidFormatError(`cbor: unexpected type for regexp: "${typeof value}"`);
        }
        let matches = value.match(/^\/(.*)\/(.*)$/);
        if (!matches || matches.length < 3) {
            throw new CBORInvalidFormatError('cbor: invalid regexp format');
        }
        return new RegExp(matches[1], matches[2]);
    };

/**
 * Default tagged values encoders.
 */
export const DEFAULT_TAGGED_ENCODERS: TaggedEncoder<any>[] = [
    DateStringEncoder,
    RegExpEncoder
];

/**
 * Default tagged values decoders.
 */
export const DEFAULT_TAGGED_DECODERS: TaggedDecoder<any>[] = [
    DateStringDecoder,
    DateNumberDecoder,
    RegExpDecoder
];

/**
 * Simple values are some predefined (see RFC 7049, Section 2.3),
 * others are assigned by IANA "CBOR Simple Values" registry
 * (Section 7.1).
 */
export class Simple {
    constructor(public value: number) { }
}

// eslint:disable-next-line: max-line-length
const ISO_DATE_RX = /^([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))$/;

/**
 * Specifies options for encoder.
 */
export type EncoderOptions = {
    /**
     * In JavaScript, object keys are strings, so by default CBOR encoding will
     * produce string keys for maps.
     *
     * Setting intKeys to true will make encoder first try to convert each
     * object key to integer and encode it as such if conversion succeeds. Keys
     * that cannot be converted will be encoded as strings. Note that if object
     * contains both integer and string keys, the map will be encoded as such.
     *
     * By default, false.
     */
    intKeys?: boolean;

    /**
     * Tagged object encoders.
     *
     * By default, DEFAULT_TAGGED_ENCODERS, which encodes Dates (as a string)
     * and RegExps.
     *
     * Pass empty array to disable tagged encoders.
     */
    taggedEncoders?: TaggedEncoder<any>[];
};

export const DEFAULT_ENCODER_OPTIONS: EncoderOptions = {
    intKeys: false,
    taggedEncoders: DEFAULT_TAGGED_ENCODERS
};

/**
 * Encoder encodes values into CBOR format.
 */
export class Encoder {
    private _buf: ByteWriter;
    private _opt: EncoderOptions;
    private _taggedEncoders: TaggedEncoder<any>[];

    constructor(options = DEFAULT_ENCODER_OPTIONS, writer = new ByteWriter()) {
        this._buf = writer;
        this._opt = options;
        this._taggedEncoders = options.taggedEncoders || DEFAULT_TAGGED_ENCODERS;
    }

    finish(): Uint8Array {
        return this._buf.finish();
    }

    reset(): this {
        this._buf.clean();
        this._buf.reset();
        return this;
    }

    clean(): void {
        this._buf.clean();
    }

    encode(value: any | null | undefined): this {
        switch (typeof value) {
            case "undefined":
                return this.encodeUndefined();
            case "boolean":
                return this.encodeBoolean(value);
            case "number":
                return this.encodeNumber(value);
            case "string":
                return this.encodeString(value);
            case "object":
                return this.encodeObject(value);
            default:
                throw new Error(`cbor: cannot encode type "${typeof value}"`);
        }
    }

    private encodeTagged(tag: number, value: any) {
        this._writeMajorTypeAndLength(MT_TAG, tag);
        return this.encode(value);
    }

    encodeSimple(value: number): this {
        if (value < 0 || value > 255) {
            throw new Error(`cbor: incorrect simple value ${value}`);
        }
        this._writeMajorTypeAndLength(MT_SIMPLE_OR_FLOAT, value);
        return this;
    }

    private _writeMajorTypeAndLength(type: number, length: number) {
        if (length < AI_8_BITS) {
            this._buf.writeByte(type << 5 | length);
        } else if (length <= MAX_UINT8) {
            this._buf.writeByte(type << 5 | AI_8_BITS);
            this._buf.writeByte(length);
        } else if (length <= MAX_UINT16) {
            this._buf.writeByte(type << 5 | AI_16_BITS);
            this._buf.writeUint16BE(length);
        } else if (length <= MAX_UINT32) {
            this._buf.writeByte(type << 5 | AI_32_BITS);
            this._buf.writeUint32BE(length);
        } else {
            this._buf.writeByte(type << 5 | AI_64_BITS);
            this._buf.writeUint64BE(length);
        }
    }

    encodeBoolean(value: boolean): this {
        if (value) {
            this._writeMajorTypeAndLength(MT_SIMPLE_OR_FLOAT, AI_TRUE);
        } else {
            this._writeMajorTypeAndLength(MT_SIMPLE_OR_FLOAT, AI_FALSE);
        }
        return this;
    }

    encodeNull(): this {
        this._writeMajorTypeAndLength(MT_SIMPLE_OR_FLOAT, AI_NULL);
        return this;
    }

    encodeUndefined(): this {
        this._writeMajorTypeAndLength(MT_SIMPLE_OR_FLOAT, AI_UNDEFINED);
        return this;
    }

    encodeNumber(value: number): this {
        if (value === 0) {
            // Distinguish between -0 and +0
            if (isNegativeZero(value)) {
                // -0. We could use this._encodeDouble(value), to encode
                // float32, but instead we'll write float16 manually.
                this._writeMajorTypeAndLength(MT_SIMPLE_OR_FLOAT, 0x8000);
            } else {
                this.encodeInteger(value); // +0
            }
        } else if (isSafeInteger(value)) {
            this.encodeInteger(value);
        } else {
            this.encodeDouble(value);
        }
        return this;
    }

    encodeInteger(value: number): this {
        if (value < 0) {
            this._writeMajorTypeAndLength(MT_NEGATIVE_INT, -(value + 1));
        } else {
            this._writeMajorTypeAndLength(MT_UNSIGNED_INT, value);
        }
        return this;
    }

    encodeDouble(value: number): this {
        // Encode some common values as float16.
        if (value === Infinity) {
            this._writeMajorTypeAndLength(MT_SIMPLE_OR_FLOAT, 0x7c00);
            return this;
        } else if (value === -Infinity) {
            this._writeMajorTypeAndLength(MT_SIMPLE_OR_FLOAT, 0xfc00);
            return this;
        } else if (isNaN(value)) {
            this._writeMajorTypeAndLength(MT_SIMPLE_OR_FLOAT, 0x7e00);
            return this;
        }

        // Find minimal encoding: float32 or float64.
        if (value === fround(value)) {
            // Can be encoded in 32 bits.
            this._buf.writeByte(MT_SIMPLE_OR_FLOAT << 5 | AI_32_BITS);
            this._buf.writeFloat32BE(value);
        } else {
            // Use full 64-bit encoding.
            this._buf.writeByte(MT_SIMPLE_OR_FLOAT << 5 | AI_64_BITS);
            this._buf.writeFloat64BE(value);
        }
        return this;
    }

    encodeString(value: string): this {
        // TODO(dchest): use byte-by-byte utf8 encoding
        // to (probably) improve performance.
        const b = encodeUTF8(value);
        this._writeMajorTypeAndLength(MT_TEXT_STRING, b.length);
        this._buf.write(b);
        return this;
    }

    encodeBytes(value: Uint8Array): this {
        this._writeMajorTypeAndLength(MT_BYTE_STRING, value.length);
        this._buf.write(value);
        return this;
    }

    encodeArray(value: Array<any | null | undefined>): this {
        this._writeMajorTypeAndLength(MT_ARRAY, value.length);
        value.forEach(item => this.encode(item));
        return this;
    }

    encodeObject(value: object | null): this {
        if (value === null) {
            return this.encodeNull();
        } else if (Array.isArray(value)) {
            return this.encodeArray(value);
        } else if (value instanceof Uint8Array) {
            return this.encodeBytes(value);
        } else if (value instanceof ArrayBuffer) {
            return this.encodeBytes(new Uint8Array(value));
        } else if (value instanceof Date) {
            return this.encodeDate(value);
        } else if (value instanceof RegExp) {
            return this.encodeRegExp(value);
        } else if (value instanceof Simple) {
            return this.encodeSimple(value.value);
        } else if (value instanceof Tagged) {
            return this.encodeTagged(value.tag, value.value);
        }

        // Try encoding tagged objects.
        for (let i = 0; i < this._taggedEncoders.length; i++) {
            const result = this._taggedEncoders[i](value);
            if (result) { // skip any falsy result
                return this.encodeTagged(result.tag, result.value);
            }
        }

        return this.encodeMap(value);
    }

    encodeMap(value: { [key: string]: (any | null | undefined) }): this {
        const keys = Object.keys(value);
        this._writeMajorTypeAndLength(MT_MAP, keys.length);
        keys.forEach(key => {
            // If intKeys option is true, try converting key to integer and
            // encode it as such. Otherwise, or if conversion fails, encode it
            // as string.
            if (this._opt.intKeys) {
                const v = parseInt(key, 10);
                // Make sure the whole key was parsed as integer.
                // NOTE: numbers with plus sign (+1) will be considered
                // strings, numbers with minus sign (-1) will be considered
                // integers.
                if (!isNaN(v) && String(v) === key) {
                    this.encodeInteger(v);
                } else {
                    this.encodeString(key);
                }
            } else {
                this.encodeString(key);
            }
            this.encode(value[key]);
        });
        return this;
    }

    encodeDate(value: Date): this {
        return this.encodeTagged(Tags.DateString, value.toISOString().slice(0, 19) + "Z");
    }

    encodeRegExp(value: RegExp): this {
        return this.encodeTagged(Tags.RegExp, value.toString());
    }
}

/**
 * Encodes the given value as CBOR.
 */
export function encode(value: any | null | undefined, options?: EncoderOptions): Uint8Array {
    const enc = new Encoder(options);
    const result = enc.encode(value).finish();
    enc.clean();
    return result;
}

/**
 * Specifies options for decoder.
 */
export type DecoderOptions = {
    /**
     * If true, instead of copying byte arrays return subarrays into CBOR
     * buffer.
     *
     * By default, false.
     */
    noCopy?: boolean;

    /**
     * If true, ignore extra data at the end of the source buffer.
     * Otherwise, decoder throws an error if extra data is detected.
     *
     * To get the number of extra bytes left, use undecodedLength.
     *
     * By default, false.
     */
    ignoreExtraData?: boolean;

    /**
     * If true, allow only string and number keys for maps.
     * Throw if encountered any other type.
     *
     * By default, false.
     */
    strictMapKeys?: boolean;

    /**
     * If true, map keys must be unique (after conversion to string).
     * Throw if encountered duplicate keys.
     *
     * By default, false.
     */
    uniqueMapKeys?: boolean;

    /**
     * Maximum allowed depth of nested structures (arrays and maps).
     * If exceeded, decoder throws an error.
     *
     * By default, 128.
     */
    maxDepth?: number;

    /**
     * Maximum allowed length of maps (number of key-value pairs).
     *
     * By default, unlimited.
     */
    maxMapLength?: number;

    /**
     * Maximum allowed length of arrays (number of items).
     *
     * By default, unlimited.
     */
    maxArrayLength?: number;

    /**
     * Maximum allowed byte length of bytes or strings.
     *
     * By default, unlimited.
     */
    maxByteLength?: number;

    /**
     * Maximum allowed length of indefinite-length items
     * (bytes, strings, arrays, maps).
     *
     * Can be set to 0 to disallow indefinite-length items.
     *
     * maxArrayLength, maxMapLength and maxByteLength options,
     * if set, still apply.
     *
     * If exceeded, decoder throws an error.
     *
     * By default, unlimited.
     */
    maxIndefiniteLength?: number;

    /**
     * Tagged object decoders.
     *
     * By default, DEFAULT_TAGGED_DECODERS, which converts tagged
     * Tags.DateString and Tags.DateNumber to Date and Tags.RegExp to RegExp
     * objects.
     *
     * Pass empty array to disable tagged decoders.
     */
    taggedDecoders?: TaggedDecoder<any>[];
};

export const DEFAULT_DECODER_OPTIONS: DecoderOptions = {
    noCopy: false,
    ignoreExtraData: false,
    maxDepth: 128,
    maxIndefiniteLength: Infinity,
    maxMapLength: Infinity,
    maxArrayLength: Infinity,
    maxByteLength: Infinity,
    taggedDecoders: DEFAULT_TAGGED_DECODERS
};

/**
 * Base class for all CBOR decoder errors.
 */
export class CBORDecodeError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "CBORDecodeError";
    }
}

/**
 * Thrown when the CBOR data is malformed or contains an unsupported encoding.
 */
export class CBORInvalidFormatError extends CBORDecodeError {
    constructor(message: string) {
        super(message);
        this.name = "CBORInvalidFormatError";
    }
}

/**
 * Thrown when there is extra data at the end of the CBOR input.
 */
export class CBORExtraDataError extends CBORDecodeError {
    constructor() {
        super("cbor: extra data at the end");
        this.name = "CBORExtraDataError";
    }
}

/**
 * Thrown when the maximum nesting depth is exceeded.
 */
export class CBORMaxDepthExceededError extends CBORDecodeError {
    readonly maxDepth: number;
    constructor(maxDepth: number) {
        super(`cbor: exceeded maximum depth of ${maxDepth}`);
        this.name = "CBORMaxDepthExceededError";
        this.maxDepth = maxDepth;
    }
}

/**
 * Thrown when a map key with a forbidden name is encountered.
 */
export class CBORForbiddenKeyError extends CBORDecodeError {
    readonly key: string;
    constructor(key: string) {
        super(`cbor: forbidden map key: "${key}"`);
        this.name = "CBORForbiddenKeyError";
        this.key = key;
    }
}

/**
 * Thrown when a duplicate map key is encountered and uniqueMapKeys is enabled.
 */
export class CBORDuplicateKeyError extends CBORDecodeError {
    readonly key: string;
    constructor(key: string) {
        super(`cbor: duplicate map key: "${key}"`);
        this.name = "CBORDuplicateKeyError";
        this.key = key;
    }
}

/**
 * Thrown when a map key has an invalid type and strictMapKeys is enabled.
 */
export class CBORInvalidKeyTypeError extends CBORDecodeError {
    readonly keyType: string;
    constructor(keyType: string) {
        super(`cbor: wrong map key type "${keyType}"`);
        this.name = "CBORInvalidKeyTypeError";
        this.keyType = keyType;
    }
}

/**
 * Thrown when reached maximum allowed length of indefinite-length items
 * and maxIndefiniteLength is enabled.
 */
export class CBORIndefiniteLengthExceededError extends CBORDecodeError {
    readonly maxIndefiniteLength: number;
    constructor(maxIndefiniteLength: number) {
        super(`cbor: exceeded maximum indefinite length of ${maxIndefiniteLength}`);
        this.name = "CBORIndefiniteLengthExceededError";
        this.maxIndefiniteLength = maxIndefiniteLength;
    }
}

/**
 * Thrown when reached maximum allowed length of maps, arrays, bytes or strings
 * and corresponding maxMapLength, maxArrayLength or maxByteLength is enabled.
 */
export class CBORLengthExceededError extends CBORDecodeError {
    readonly maxLength: number;
    constructor(maxLength: number) {
        super(`cbor: exceeded maximum length of ${maxLength}`);
        this.name = "CBORLengthExceededError";
        this.maxLength = maxLength;
    }
}

/**
 * Decoder decodes values from CBOR format.
 */
export class Decoder {
    private _r: ByteReader;
    private _opt: DecoderOptions;
    private _taggedDecoders: TaggedDecoder<any>[];
    private _maxDepth: number;
    private _maxIndefiniteLength: number;
    private _maxMapLength: number;
    private _maxArrayLength: number;
    private _maxByteLength: number;
    private _depth = 0;

    /**
     * Creates decoder.
     * If noCopy is true, all read Uint8Arrays will be the subarrays of src.
     *
     * If ignoreExtraData is true, decoder will not throw if there's undecoded
     * data at the end of the source.
     */
    constructor(src: Uint8Array, options = DEFAULT_DECODER_OPTIONS) {
        this._r = new ByteReader(src);
        this._opt = { ...DEFAULT_DECODER_OPTIONS, ...options };
        this._maxDepth = this._opt.maxDepth || 128;
        if (!Number.isSafeInteger(this._maxDepth) || this._maxDepth <= 0) {
            this._maxDepth = 128;
        }
        this._maxIndefiniteLength = this._opt.maxIndefiniteLength !== undefined ? this._opt.maxIndefiniteLength : Infinity;
        this._maxArrayLength = this._opt.maxArrayLength !== undefined ? this._opt.maxArrayLength : Infinity;
        this._maxMapLength = this._opt.maxMapLength !== undefined ? this._opt.maxMapLength : Infinity;
        this._maxByteLength = this._opt.maxByteLength !== undefined ? this._opt.maxByteLength : Infinity;
        this._taggedDecoders = this._opt.taggedDecoders || DEFAULT_TAGGED_DECODERS;
    }

    decode(): any | null | undefined {
        this._depth = 0;
        const result = this._decodeValue();
        if (!this._opt.ignoreExtraData && this.undecodedLength !== 0) {
            throw new CBORExtraDataError();
        }
        return result;
    }

    /**
     * Gets the number of undecoded bytes left in the buffer.
     */
    get undecodedLength(): number {
        return this._r.unreadLength;
    }

    private _readLength(additionalInfo: number): number {
        if (additionalInfo < AI_8_BITS) {
            return additionalInfo;
        } else if (additionalInfo === AI_8_BITS) {
            return this._r.readByte();
        } else if (additionalInfo === AI_16_BITS) {
            return this._r.readUint16BE();
        } else if (additionalInfo === AI_32_BITS) {
            return this._r.readUint32BE();
        } else if (additionalInfo === AI_64_BITS) {
            const value = this._r.readUint64BE();
            if (!isSafeInteger(value)) {
                throw new CBORInvalidFormatError("cbor: 64-bit value is too large");
            }
            return value;
        } else if (additionalInfo === AI_STOP) {
            return Infinity; // indefinite-length item
        } else {
            throw new CBORInvalidFormatError("cbor: unsupported (reserved) length");
        }
    }

    private _decodeValue(firstByte = this._r.readByte()): any | null | undefined {
        const majorType = firstByte >> 5;
        const additionalInfo = firstByte & 31;

        // Read float/simple early to avoid reading length.
        if (majorType === MT_SIMPLE_OR_FLOAT) {
            return this._decodeSimpleOrFloat(additionalInfo);
        }

        const length = this._readLength(additionalInfo);

        switch (majorType) {
            case MT_UNSIGNED_INT:
                return this._decodeUnsignedInteger(length);
            case MT_NEGATIVE_INT:
                return this._decodeNegativeInteger(length);
            case MT_BYTE_STRING:
                return this._decodeBytes(length);
            case MT_TEXT_STRING:
                return this._decodeString(length);
            case MT_ARRAY:
                return this._decodeArray(length);
            case MT_MAP:
                return this._decodeMap(length);
            case MT_TAG:
                return this._decodeTagged(length);
            default:
                // Note: MT_SIMPLE_OR_FLOAT is decoded earlier.
                throw new CBORInvalidFormatError(`cbor: unexpected major type ${majorType}`);
        }
    }

    private _decodeSimple(value: number): any | null | undefined {
        switch (value) {
            case AI_FALSE:
                return false;
            case AI_TRUE:
                return true;
            case AI_NULL:
                return null;
            case AI_UNDEFINED:
                return undefined;
            case AI_STOP:
                // Note: AI_STOP is handled by indefinite readers.
                throw new Error("cbor: programmer error! Stop not handled.");
            default:
                return new Simple(value);
        }
    }

    private _decodeSimpleOrFloat(additionalInfo: number): number {
        if (additionalInfo < AI_8_BITS) {
            return this._decodeSimple(additionalInfo);
        } else if (additionalInfo === AI_8_BITS) {
            return this._decodeSimple(this._r.readByte());
        } else if (additionalInfo === AI_16_BITS) {
            return this._decodeFloat16();
        } else if (additionalInfo === AI_32_BITS) {
            return this._r.readFloat32BE();
        } else if (additionalInfo === AI_64_BITS) {
            return this._r.readFloat64BE();
        } else {
            // Note: AI_STOP is handled by indefinite readers.
            throw new CBORInvalidFormatError("cbor: unsupported float length");
        }
    }

    private _decodeFloat16(): number {
        let u = this._r.readUint16BE();
        let exponent = (u & 0x7C00) >> 10;
        let fraction = u & 0x03FF;

        let value: number;
        if (exponent === 0) {
            value = 6.103515625e-5 * (fraction / 0x400);
        } else if (exponent === 0x1f) {
            value = fraction ? NaN : Infinity;
        } else {
            value = Math.pow(2, exponent - 15) * (1 + fraction / 0x400);
        }
        if (u & 0x8000) {
            return -value;
        } else {
            return value;
        }
    }

    private _decodeUnsignedInteger(length: number): number {
        return length;
    }

    private _decodeNegativeInteger(length: number): number {
        return -1 - length;
    }

    private _decodeString(length: number): string {
        // TODO(dchest): make utf8 decoding inline.
        if (length === Infinity) {
            return this._decodeIndefiniteString();
        }
        if (length > this._maxByteLength) {
            throw new CBORLengthExceededError(this._maxByteLength);
        }
        return decodeUTF8(this._r.readNoCopy(length));
    }

    private _decodeIndefiniteString(): string {
        let result = "";
        let b: number;
        let n = 0;
        while ((b = this._r.readByte()) !== STOP_BYTE) {
            if (++n > this._maxIndefiniteLength) {
                throw new CBORIndefiniteLengthExceededError(this._maxIndefiniteLength);
            }
            if (n > this._maxByteLength) {
                throw new CBORLengthExceededError(this._maxByteLength);
            }
            const majorType = b >> 5;
            const length = this._readLength(b & 31);
            if (majorType !== MT_TEXT_STRING || length === Infinity) {
                throw new CBORInvalidFormatError("cbor: incorrect indefinite string encoding");
            }
            result += decodeUTF8(this._r.readNoCopy(length));
        }
        return result;
    }

    private _decodeBytes(length: number): Uint8Array {
        if (length === Infinity) {
            return this._decodeIndefiniteBytes();
        }
        if (length > this._maxByteLength) {
            throw new CBORLengthExceededError(this._maxByteLength);
        }
        if (this._opt.noCopy) {
            return this._r.readNoCopy(length);
        }
        return this._r.read(length);
    }

    private _decodeIndefiniteBytes(): Uint8Array {
        let buf = new ByteWriter();
        let b: number;
        let n = 0;
        while ((b = this._r.readByte()) !== STOP_BYTE) {
            if (++n > this._maxIndefiniteLength) {
                throw new CBORIndefiniteLengthExceededError(this._maxIndefiniteLength);
            }
            if (n > this._maxByteLength) {
                throw new CBORLengthExceededError(this._maxByteLength);
            }
            const majorType = b >> 5;
            const length = this._readLength(b & 31);
            if (majorType !== MT_BYTE_STRING || length === Infinity) {
                throw new CBORInvalidFormatError(`cbor: incorrect indefinite bytes encoding (type=${majorType})`);
            }
            buf.write(this._r.readNoCopy(length));
        }
        const result = buf.finish();
        buf.clean();
        return result;
    }

    private _decodeArray(length: number): Array<any | null | undefined> {
        if (length === Infinity) {
            return this._decodeIndefiniteArray();
        }
        if (++this._depth > this._maxDepth) {
            throw new CBORMaxDepthExceededError(this._maxDepth);
        }
        if (length > this._maxArrayLength) {
            throw new CBORLengthExceededError(this._maxArrayLength);
        }
        const result: Array<any | null | undefined> = [];
        for (let i = 0; i < length; i++) {
            result.push(this._decodeValue());
        }
        this._depth--;
        return result;
    }

    private _decodeIndefiniteArray(): Array<any | null | undefined> {
        if (++this._depth > this._maxDepth) {
            throw new CBORMaxDepthExceededError(this._maxDepth);
        }
        const result: Array<any | null | undefined> = [];
        let b: number;
        let n = 0;
        while ((b = this._r.readByte()) !== STOP_BYTE) {
            if (++n > this._maxIndefiniteLength) {
                throw new CBORIndefiniteLengthExceededError(this._maxIndefiniteLength);
            }
            if (n > this._maxArrayLength) {
                throw new CBORLengthExceededError(this._maxArrayLength);
            }
            result.push(this._decodeValue(b));
        }
        this._depth--;
        return result;
    }

    private _decodeMap(length: number): { [key: string]: (any | null | undefined) } {
        if (length === Infinity) {
            return this._decodeIndefiniteMap();
        }
        if (++this._depth > this._maxDepth) {
            throw new CBORMaxDepthExceededError(this._maxDepth);
        }
        if (length > this._maxMapLength) {
            throw new CBORLengthExceededError(this._maxMapLength);
        }
        const result: { [key: string]: (any | null | undefined) } = {};
        for (let i = 0; i < length; i++) {
            const key = this._decodeValue();
            if (this._opt.strictMapKeys &&
                (typeof key !== "number" && typeof key !== "string")) {
                throw new CBORInvalidKeyTypeError(typeof key);
            }
            if (this._opt.uniqueMapKeys && Object.prototype.hasOwnProperty.call(result, key)) {
                throw new CBORDuplicateKeyError(key);
            }
            if (key === "__proto__" || key === "constructor" || key === "prototype") {
                throw new CBORForbiddenKeyError(key);
            }
            const value = this._decodeValue();
            result[key] = value;
        }
        this._depth--;
        return result;
    }

    private _decodeIndefiniteMap(): { [key: string]: (any | null | undefined) } {
        if (++this._depth > this._maxDepth) {
            throw new CBORMaxDepthExceededError(this._maxDepth);
        }
        const result: { [key: string]: (any | null | undefined) } = {};
        let b: number;
        let n = 0;
        while ((b = this._r.readByte()) !== STOP_BYTE) {
            if (++n > this._maxIndefiniteLength) {
                throw new CBORIndefiniteLengthExceededError(this._maxIndefiniteLength);
            }
            if (n > this._maxMapLength) {
                throw new CBORLengthExceededError(this._maxMapLength);
            }
            const key = this._decodeValue(b);
            if (this._opt.strictMapKeys &&
                (typeof key !== "number" && typeof key !== "string")) {
                throw new CBORInvalidKeyTypeError(typeof key);
            }
            if (this._opt.uniqueMapKeys && Object.prototype.hasOwnProperty.call(result, key)) {
                throw new CBORDuplicateKeyError(key);
            }
            if (key === "__proto__" || key === "constructor" || key === "prototype") {
                throw new CBORForbiddenKeyError(key);
            }
            const value = this._decodeValue();
            result[key] = value;
        }
        this._depth--;
        return result;
    }

    private _decodeTagged(tag: number): (any | null | undefined) {
        const tagged = new Tagged(tag, this._decodeValue());
        for (let i = 0; i < this._taggedDecoders.length; i++) {
            const result = this._taggedDecoders[i](tagged);
            if (result !== undefined) {
                return result;
            }
        }
        return tagged;
    }
}

/**
 * Decodes src from CBOR.
 *
 * If noCopy is true, the returned Uint8Arrays will be a subarrays of src
 * otherwise they will be newly allocated. It is not recommended to set it to
 * true, due to the possibility of hard-to-detect bugs resulting from it and
 * preventing chunks of memory from being garbage collected.
 *
 * If ignoreExtraData is true, decoder will not throw an error if there's
 * undecoded data at the end of the source.
 */
export function decode(src: Uint8Array, options?: DecoderOptions): any | null | undefined {
    return new Decoder(src, options).decode();
}
