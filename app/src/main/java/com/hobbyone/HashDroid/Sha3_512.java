/* Sha3_512.java --
   SHA3-512 message digest, built on the Keccak sponge engine.

   This file is part of Hash Droid.

   Hash Droid is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
 */

package com.hobbyone.HashDroid;

/**
 * <p>
 * The SHA3-512 message digest algorithm as standardized in FIPS 202.
 * </p>
 */
public final class Sha3_512 implements IMessageDigest {

    private static final String KNOWN_EMPTY_DIGEST =
            "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26";

    private Keccak core;

    public Sha3_512() {
        core = new Keccak(64);
    }

    private Sha3_512(Sha3_512 src) {
        core = new Keccak(src.core);
    }

    public String name() {
        return "SHA3-512";
    }

    public int hashSize() {
        return 64;
    }

    public int blockSize() {
        return core.rate();
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
        byte[] md = new Sha3_512().digest();
        return UtilServices.toString(md).equalsIgnoreCase(KNOWN_EMPTY_DIGEST);
    }

    public Object clone() {
        return new Sha3_512(this);
    }
}
