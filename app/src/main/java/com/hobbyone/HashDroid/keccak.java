/* Keccak.java --
   Core Keccak-f[1600] sponge implementation used by SHA3-256 and SHA3-512.

   This is a Java port of the public-domain "tiny_sha3" reference
   implementation by Markku-Juhani O. Saarinen (CC0), adapted to the
   FIPS 202 SHA-3 padding rule (suffix 0x06).

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
 * Internal sponge-construction engine implementing the Keccak-f[1600]
 * permutation, configured for the SHA-3 family of hash functions.
 * </p>
 */
final class Keccak {

    // Round constants (iota step)
    private static final long[] RNDC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    // Rotation offsets (rho step)
    private static final int[] ROTC = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };

    // Lane permutation indices (pi step)
    private static final int[] PILN = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };

    private final byte[] st = new byte[200];
    private final int rate;   // block/rate size in bytes
    private final int outLen; // digest length in bytes
    private int pt;

    Keccak(int outLenBytes) {
        this.outLen = outLenBytes;
        this.rate = 200 - 2 * outLenBytes;
        this.pt = 0;
    }

    Keccak(Keccak src) {
        this.outLen = src.outLen;
        this.rate = src.rate;
        this.pt = src.pt;
        System.arraycopy(src.st, 0, this.st, 0, 200);
    }

    int rate() {
        return rate;
    }

    int outLen() {
        return outLen;
    }

    void reset() {
        Arrays.fill(st, (byte) 0);
        pt = 0;
    }

    void update(byte[] data, int offset, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            st[j++] ^= data[offset + i];
            if (j >= rate) {
                keccakf();
                j = 0;
            }
        }
        pt = j;
    }

    byte[] digest() {
        st[pt] ^= 0x06;
        st[rate - 1] ^= (byte) 0x80;
        keccakf();

        byte[] out = new byte[outLen];
        System.arraycopy(st, 0, out, 0, outLen);
        reset();
        return out;
    }

    private void keccakf() {
        long[] a = new long[25];
        for (int i = 0; i < 25; i++) {
            long v = 0;
            for (int b = 0; b < 8; b++) {
                v |= (st[i * 8 + b] & 0xFFL) << (8 * b);
            }
            a[i] = v;
        }

        long[] bc = new long[5];
        for (int round = 0; round < 24; round++) {
            // Theta
            for (int i = 0; i < 5; i++)
                bc[i] = a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20];
            for (int i = 0; i < 5; i++) {
                long t = bc[(i + 4) % 5] ^ Long.rotateLeft(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5)
                    a[j + i] ^= t;
            }

            // Rho and Pi
            long t = a[1];
            for (int i = 0; i < 24; i++) {
                int j = PILN[i];
                long tmp = a[j];
                a[j] = Long.rotateLeft(t, ROTC[i]);
                t = tmp;
            }

            // Chi
            for (int j = 0; j < 25; j += 5) {
                long b0 = a[j], b1 = a[j + 1], b2 = a[j + 2], b3 = a[j + 3], b4 = a[j + 4];
                a[j] ^= (~b1) & b2;
                a[j + 1] ^= (~b2) & b3;
                a[j + 2] ^= (~b3) & b4;
                a[j + 3] ^= (~b4) & b0;
                a[j + 4] ^= (~b0) & b1;
            }

            // Iota
            a[0] ^= RNDC[round];
        }

        for (int i = 0; i < 25; i++) {
            long v = a[i];
            for (int b = 0; b < 8; b++) {
                st[i * 8 + b] = (byte) (v & 0xFF);
                v >>>= 8;
            }
        }
    }
}
