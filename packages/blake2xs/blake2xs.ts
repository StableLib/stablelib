import { Hash } from "@stablelib/hash";
import { BLAKE2s, DIGEST_LENGTH, BLOCK_SIZE, Config } from "@stablelib/blake2s";
import { wipe } from "@stablelib/wipe";

export { BLOCK_SIZE };

/** Maximum output length */
export const MAX_DIGEST_LENGTH = 65534;

/** Indicates when ouput length is unknown */
const UNKNOWN_DIGEST_LENGTH = 65535;

function nodeOffsetWithXOFDigestLength(nodeOffset: number, digestLength: number): number {
    // Node offset is limited to 4 bytes in BLAKE2Xs.
    if (nodeOffset > Math.pow(2, 32) - 1) {
        throw new Error(`BLAKE2Xs: node offset ${nodeOffset} it too big`);
    }
    return digestLength * 0x100000000 + nodeOffset;
}

export class BLAKE2Xs implements Hash {
    readonly blockSize = BLOCK_SIZE;

    private _hash: BLAKE2s; // root hash
    private _h0?: Uint8Array; // root hash digest. Undefined if hash is not finished yet
    private _buf = new Uint8Array(DIGEST_LENGTH); // output buffer
    private _bufPos = DIGEST_LENGTH; // position in output buffer, initialized to its end
    private _outConfig: Config;
    private _left: number; // number of bytes of digestLength left to generate

    /**
     * Creates a new BLAKE2Xs instance with the given digest length. If digest
     * length is not given, it's considered unknown in advance, thus allowing
     * to generate any number of bytes up to 2^32-1.
     */
    constructor(public digestLength = UNKNOWN_DIGEST_LENGTH, config?: Config) {
        if (digestLength <= 0 || digestLength > UNKNOWN_DIGEST_LENGTH) {
            throw new Error("BLAKE2Xs: incorrect digest length");
        }
        const rootConfig = {
            ...config,
            tree: (config && config.tree) ? config.tree : {
                fanout: 1,
                maxDepth: 1,
                leafSize: 0,
                nodeOffset: 0,
                nodeDepth: 0,
                innerDigestLength: 0,
                lastNode: false
            }
        };

        rootConfig.tree.nodeOffset = nodeOffsetWithXOFDigestLength(
            rootConfig.tree.nodeOffset,
            digestLength
        );

        this._hash = new BLAKE2s(DIGEST_LENGTH, rootConfig);

        this._outConfig = {
            ...rootConfig,
            key: undefined,
            tree: {
                fanout: 0,
                maxDepth: 0,
                leafSize: DIGEST_LENGTH,
                nodeOffset: nodeOffsetWithXOFDigestLength(0, digestLength),
                nodeDepth: 0,
                innerDigestLength: DIGEST_LENGTH,
                lastNode: false
            }
        };

        this._left = digestLength;
    }

    update(data: Uint8Array, dataLength = data.length): this {
        this._hash.update(data, dataLength);
        return this;
    }

    stream(dst: Uint8Array): this {
        if (!this._h0) {
            // Finish root hash to get h0.
            this._h0 = new Uint8Array(DIGEST_LENGTH);
            this._hash.finish(this._h0);
        }
        if (dst.length === 0) {
            return this;
        }
        if (dst.length > this._left) {
            throw new Error("BLAKE2Xs: cannot generate more bytes");
        }
        for (let i = 0; i < dst.length; i++) {
            if (this._bufPos >= DIGEST_LENGTH) {
                // Fill buffer.
                const dlen = (this._left < DIGEST_LENGTH) ? this._left : DIGEST_LENGTH;
                const h = new BLAKE2s(dlen, this._outConfig);
                h.update(this._h0);
                h.finish(this._buf);
                h.clean();
                this._bufPos = 0;
                this._outConfig.tree!.nodeOffset++;
            }
            dst[i] = this._buf[this._bufPos];
            this._bufPos++;
            this._left--;
        }
        return this;
    }

    finish = this.stream;

    digest(): Uint8Array {
        const out = new Uint8Array(this.digestLength);
        this.finish(out);
        return out;
    }

    reset(): this {
        this._hash.reset();
        this._h0 = undefined;
        return this;
    }

    clean() {
        this._hash.clean();
        wipe(this._buf);
        this._bufPos = 0;
        this.digestLength = 0;
    }
}

export function xof(digestLength: number, data: Uint8Array, key?: Uint8Array): Uint8Array {
    const h = new BLAKE2Xs(digestLength, { key });
    h.update(data);
    const out = h.digest();
    h.clean();
    return out;
}
