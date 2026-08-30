/* Blake2b.java --
   Core BLAKE2b compression engine, as specified in RFC 7693.

   This is an unkeyed, straightforward Java implementation of the
   BLAKE2b hash function (used here for its 512-bit output).

   This file is part of Hash Droid.

   Hash Droid is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
 */

package com.hobbyone.HashDroid;

import java.util.Arrays;

/**
 * <p>
 * Internal, unkeyed BLAKE2b engine implementing the compression
 * function and streaming buffer logic described in RFC 7693.
 * </p>
 */
final class Blake2b {

    private static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    private static final int[][] SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };

    private final long[] h = new long[8];
    private final byte[] buf = new byte[128];
    private int buflen;
    private long t0, t1;
    private final int outLen;

    Blake2b(int outLenBytes) {
        this.outLen = outLenBytes;
        reset();
    }

    Blake2b(Blake2b src) {
        this.outLen = src.outLen;
        System.arraycopy(src.h, 0, this.h, 0, 8);
        System.arraycopy(src.buf, 0, this.buf, 0, 128);
        this.buflen = src.buflen;
        this.t0 = src.t0;
        this.t1 = src.t1;
    }

    int outLen() {
        return outLen;
    }

    void reset() {
        System.arraycopy(IV, 0, h, 0, 8);
        h[0] ^= 0x01010000L ^ outLen; // no key, digest length = outLen
        buflen = 0;
        t0 = 0;
        t1 = 0;
        Arrays.fill(buf, (byte) 0);
    }

    void update(byte[] data, int offset, int len) {
        int i = 0;
        while (i < len) {
            if (buflen == 128) {
                advanceCounter(128);
                compress(false);
                buflen = 0;
            }
            int toCopy = Math.min(128 - buflen, len - i);
            System.arraycopy(data, offset + i, buf, buflen, toCopy);
            buflen += toCopy;
            i += toCopy;
        }
    }

    byte[] digest() {
        advanceCounter(buflen);
        for (int i = buflen; i < 128; i++) buf[i] = 0;
        compress(true);

        byte[] out = new byte[outLen];
        for (int i = 0; i < outLen; i++) {
            out[i] = (byte) (h[i / 8] >>> (8 * (i % 8)));
        }
        reset();
        return out;
    }

    private void advanceCounter(int inc) {
        // t0 is a 64-bit byte counter; wrap-around would require hashing an
        // exabyte-scale input, which is outside the scope of this app, so t1
        // (the high word) is intentionally left untouched.
        t0 += inc;
    }

    private void compress(boolean last) {
        long[] m = new long[16];
        for (int i = 0; i < 16; i++) {
            long v = 0;
            for (int b = 0; b < 8; b++) {
                v |= (buf[i * 8 + b] & 0xFFL) << (8 * b);
            }
            m[i] = v;
        }

        long[] v = new long[16];
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= t0;
        v[13] ^= t1;
        if (last) v[14] = ~v[14];

        for (int round = 0; round < 12; round++) {
            int[] s = SIGMA[round];
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private static void g(long[] v, int a, int b, int c, int d, long x, long y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }
}
