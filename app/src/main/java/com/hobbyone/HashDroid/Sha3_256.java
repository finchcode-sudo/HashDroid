/* Sha3_256.java --
   SHA3-256 message digest, built on the Keccak sponge engine.

   This file is part of Hash Droid.

   Hash Droid is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
 */

package com.hobbyone.HashDroid;

/**
 * <p>
 * The SHA3-256 message digest algorithm as standardized in FIPS 202.
 * </p>
 */
public final class Sha3_256 implements IMessageDigest {

    private static final String KNOWN_EMPTY_DIGEST =
            "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434";

    private Keccak core;

    public Sha3_256() {
        core = new Keccak(32);
    }

    private Sha3_256(Sha3_256 src) {
        core = new Keccak(src.core);
    }

    public String name() {
        return "SHA3-256";
    }

    public int hashSize() {
        return 32;
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
        byte[] md = new Sha3_256().digest();
        return UtilServices.toString(md).equalsIgnoreCase(KNOWN_EMPTY_DIGEST);
    }

    public Object clone() {
        return new Sha3_256(this);
    }
}
