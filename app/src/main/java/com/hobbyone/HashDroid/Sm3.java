/* Sm3.java --
   SM3 cryptographic hash algorithm (Chinese national standard,
   GB/T 32905-2016 / GM/T 0004-2012), pure Java implementation.

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
 * The SM3 cryptographic hash algorithm, China's national standard
 * hash function (256-bit output, 512-bit block size).
 * </p>
 */
public final class Sm3 implements IMessageDigest {

    private static final String KNOWN_EMPTY_DIGEST =
            "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B";

    private static final int[] IV = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    private int[] v = new int[8];
    private byte[] buf = new byte[64];
    private int buflen;
    private long bitLen;

    public Sm3() {
        reset();
    }

    private Sm3(Sm3 src) {
        v = src.v.clone();
        buf = src.buf.clone();
        buflen = src.buflen;
        bitLen = src.bitLen;
    }

    public String name() {
        return "SM3";
    }

    public int hashSize() {
        return 32;
    }

    public int blockSize() {
        return 64;
    }

    public void reset() {
        System.arraycopy(IV, 0, v, 0, 8);
        buflen = 0;
        bitLen = 0;
        Arrays.fill(buf, (byte) 0);
    }

    public void update(byte b) {
        update(new byte[]{b}, 0, 1);
    }

    public void update(byte[] in) {
        update(in, 0, in.length);
    }

    public void update(byte[] in, int offset, int length) {
        bitLen += (long) length * 8;
        int i = 0;
        while (i < length) {
            int toCopy = Math.min(64 - buflen, length - i);
            System.arraycopy(in, offset + i, buf, buflen, toCopy);
            buflen += toCopy;
            i += toCopy;
            if (buflen == 64) {
                compress(buf, 0);
                buflen = 0;
            }
        }
    }

    public byte[] digest() {
        long savedBitLen = bitLen;

        // Padding: 0x80, then zeros until length % 64 == 56, then 8-byte big-endian bit length
        byte[] tail = new byte[buflen + 1 + 8 + 63]; // generous scratch, trimmed below
        int pos = 0;
        System.arraycopy(buf, 0, tail, 0, buflen);
        pos = buflen;
        tail[pos++] = (byte) 0x80;

        int mod = pos % 64;
        int zeros = (mod <= 56) ? (56 - mod) : (120 - mod);
        pos += zeros;
        for (int i = pos - zeros; i < pos; i++) tail[i] = 0;

        for (int i = 7; i >= 0; i--) {
            tail[pos++] = (byte) (savedBitLen >>> (8 * i));
        }

        for (int off = 0; off < pos; off += 64) {
            compress(tail, off);
        }

        byte[] out = new byte[32];
        for (int i = 0; i < 8; i++) {
            out[i * 4] = (byte) (v[i] >>> 24);
            out[i * 4 + 1] = (byte) (v[i] >>> 16);
            out[i * 4 + 2] = (byte) (v[i] >>> 8);
            out[i * 4 + 3] = (byte) (v[i]);
        }
        reset();
        return out;
    }

    private static int rotl(int x, int n) {
        n &= 31;
        return (x << n) | (x >>> (32 - n));
    }

    private static int p0(int x) {
        return x ^ rotl(x, 9) ^ rotl(x, 17);
    }

    private static int p1(int x) {
        return x ^ rotl(x, 15) ^ rotl(x, 23);
    }

    private static int ff(int x, int y, int z, int j) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | (x & z) | (y & z);
    }

    private static int gg(int x, int y, int z, int j) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | ((~x) & z);
    }

    private static int t(int j) {
        return j < 16 ? 0x79cc4519 : 0x7a879d8a;
    }

    private void compress(byte[] block, int off) {
        int[] w = new int[68];
        for (int i = 0; i < 16; i++) {
            w[i] = ((block[off + i * 4] & 0xFF) << 24)
                    | ((block[off + i * 4 + 1] & 0xFF) << 16)
                    | ((block[off + i * 4 + 2] & 0xFF) << 8)
                    | (block[off + i * 4 + 3] & 0xFF);
        }
        for (int j = 16; j < 68; j++) {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^ rotl(w[j - 13], 7) ^ w[j - 6];
        }
        int[] wp = new int[64];
        for (int j = 0; j < 64; j++) {
            wp[j] = w[j] ^ w[j + 4];
        }

        int a = v[0], b = v[1], c = v[2], d = v[3];
        int e = v[4], f = v[5], g = v[6], h = v[7];

        for (int j = 0; j < 64; j++) {
            int ss1 = rotl(rotl(a, 12) + e + rotl(t(j), j % 32), 7);
            int ss2 = ss1 ^ rotl(a, 12);
            int tt1 = ff(a, b, c, j) + d + ss2 + wp[j];
            int tt2 = gg(e, f, g, j) + h + ss1 + w[j];
            d = c;
            c = rotl(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = rotl(f, 19);
            f = e;
            e = p0(tt2);
        }

        v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
        v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
    }

    public boolean selfTest() {
        byte[] md = new Sm3().digest();
        return UtilServices.toString(md).equalsIgnoreCase(KNOWN_EMPTY_DIGEST);
    }

    public Object clone() {
        return new Sm3(this);
    }
}
