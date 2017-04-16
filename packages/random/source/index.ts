// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

export interface RandomSource {

    /**
     * Returns the availability of random source.
     * A source can only be used if isAvailable returns true.
     */
    isAvailable: boolean;

    /**
     * Fill out with random bytes and return it.
     */
    randomBytes(length: number): Uint8Array;
}
