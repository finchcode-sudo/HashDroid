/* Blake2b512.java --
   BLAKE2b-512 message digest, built on the Blake2b compression engine.

   This file is part of Hash Droid.

   Hash Droid is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
 */

package com.hobbyone.HashDroid;

/**
 * <p>
 * The unkeyed BLAKE2b message digest algorithm with a 512-bit (64-byte)
 * output, as specified in RFC 7693.
 * </p>
 */
public final class Blake2b512 implements IMessageDigest {

    private static final String KNOWN_EMPTY_DIGEST =
            "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE8";

    private Blake2b core;

    public Blake2b512() {
        core = new Blake2b(64);
    }

    private Blake2b512(Blake2b512 src) {
        core = new Blake2b(src.core);
    }

    public String name() {
        return "BLAKE2b-512";
    }

    public int hashSize() {
        return 64;
    }

    public int blockSize() {
        return 128;
    }

    public void update(byte b) {
        core.update(new byte[]{b}, 0, 1);
    }

    public void update(byte[] in) {
        core.update(in, 0, in.length);
    }

    public void update(byte[] in, int offset, int length) {
        core.update(in, offset, length);
    }

    public byte[] digest() {
        return core.digest();
    }

    public void reset() {
        core.reset();
    }

    public boolean selfTest() {
        byte[] md = new Blake2b512().digest();
        return UtilServices.toString(md).equalsIgnoreCase(KNOWN_EMPTY_DIGEST);
    }

    public Object clone() {
        return new Blake2b512(this);
    }
}
