/* Sha224.java --
   SHA-224 message digest.

   SHA-224 reuses the exact same compression function as SHA-256 (see
   Sha256.java), differing only in its initial hash values and in that
   its final output is truncated to 224 bits (the H7 word is dropped).
*/

package com.hobbyone.HashDroid;

/**
 * <p>
 * Implementation of SHA-224 per FIPS 180-4.
 * </p>
 */
public class Sha224 extends BaseHash {

    // Constants and variables
    // -------------------------------------------------------------------------
    private static final int BLOCK_SIZE = 64; // inner block size in bytes

    private static final String DIGEST0 = "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA";

    /**
     * caches the result of the correctness test, once executed.
     */
    private static Boolean valid;

    /**
     * 256-bit interim result; only the first 224 bits (h0..h6) are emitted.
     */
    private int h0, h1, h2, h3, h4, h5, h6, h7;

    // Constructor(s)
    // -------------------------------------------------------------------------

    /**
     * Trivial 0-arguments constructor.
     */
    public Sha224() {
        super("sha-224", 28, BLOCK_SIZE);
    }

    /**
     * <p>
     * Private constructor for cloning purposes.
     * </p>
     *
     * @param md the instance to clone.
     */
    private Sha224(Sha224 md) {
        this();

        this.h0 = md.h0;
        this.h1 = md.h1;
        this.h2 = md.h2;
        this.h3 = md.h3;
        this.h4 = md.h4;
        this.h5 = md.h5;
        this.h6 = md.h6;
        this.h7 = md.h7;
        this.count = md.count;
        this.buffer = (byte[]) md.buffer.clone();
    }

    // Instance methods
    // -------------------------------------------------------------------------

    // java.lang.Cloneable interface implementation ----------------------------

    public Object clone() {
        return new Sha224(this);
    }

    // Implementation of concrete methods in BaseHash --------------------------

    protected void transform(byte[] in, int offset) {
        int[] result = Sha256.G(h0, h1, h2, h3, h4, h5, h6, h7, in, offset);

        h0 = result[0];
        h1 = result[1];
        h2 = result[2];
        h3 = result[3];
        h4 = result[4];
        h5 = result[5];
        h6 = result[6];
        h7 = result[7];
    }

    protected byte[] padBuffer() {
        int n = (int) (count % BLOCK_SIZE);
        int padding = (n < 56) ? (56 - n) : (120 - n);
        byte[] result = new byte[padding + 8];

        // padding is always binary 1 followed by binary 0s
        result[0] = (byte) 0x80;

        // save number of bits, casting the long to an array of 8 bytes
        long bits = count << 3;
        result[padding++] = (byte) (bits >>> 56);
        result[padding++] = (byte) (bits >>> 48);
        result[padding++] = (byte) (bits >>> 40);
        result[padding++] = (byte) (bits >>> 32);
        result[padding++] = (byte) (bits >>> 24);
        result[padding++] = (byte) (bits >>> 16);
        result[padding++] = (byte) (bits >>> 8);
        result[padding] = (byte) bits;

        return result;
    }

    protected byte[] getResult() {
        // SHA-224 output is SHA-256's internal state truncated to 224 bits;
        // h7 is computed but never emitted.
        return new byte[]{(byte) (h0 >>> 24), (byte) (h0 >>> 16),
                (byte) (h0 >>> 8), (byte) h0, (byte) (h1 >>> 24),
                (byte) (h1 >>> 16), (byte) (h1 >>> 8), (byte) h1,
                (byte) (h2 >>> 24), (byte) (h2 >>> 16), (byte) (h2 >>> 8),
                (byte) h2, (byte) (h3 >>> 24), (byte) (h3 >>> 16),
                (byte) (h3 >>> 8), (byte) h3, (byte) (h4 >>> 24),
                (byte) (h4 >>> 16), (byte) (h4 >>> 8), (byte) h4,
                (byte) (h5 >>> 24), (byte) (h5 >>> 16), (byte) (h5 >>> 8),
                (byte) h5, (byte) (h6 >>> 24), (byte) (h6 >>> 16),
                (byte) (h6 >>> 8), (byte) h6};
    }

    protected void resetContext() {
        // magic SHA-224 initialisation constants (FIPS 180-4 section 5.3.2)
        h0 = 0xc1059ed8;
        h1 = 0x367cd507;
        h2 = 0x3070dd17;
        h3 = 0xf70e5939;
        h4 = 0xffc00b31;
        h5 = 0x68581511;
        h6 = 0x64f98fa7;
        h7 = 0xbefa4fa4;
    }

    public boolean selfTest() {
        if (valid == null) {
            Sha224 md = new Sha224();
            md.update((byte) 0x61); // a
            md.update((byte) 0x62); // b
            md.update((byte) 0x63); // c
            String result = UtilServices.toString(md.digest());
            valid = Boolean.valueOf(DIGEST0.equals(result));
        }

        return valid.booleanValue();
    }
}
