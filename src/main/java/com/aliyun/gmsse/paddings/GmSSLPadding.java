package com.aliyun.gmsse.paddings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;

/**
 * A padder that adds GmSSL padding to a block.
 */
public class GmSSLPadding implements BlockCipherPadding {
    /**
     * Initialise the padder.
     *
     * @param random - a SecureRandom if available.
     */
    public void init(SecureRandom random)
            throws IllegalArgumentException {
        // nothing to do.
    }

    /**
     * Return the name of the algorithm the padder implements.
     *
     * @return the name of the algorithm the padder implements.
     */
    public String getPaddingName() {
        return "GMSSLPadding";
    }

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     */
    public int addPadding(
            byte[] in,
            int inOff) {
        byte code = (byte) (in.length - inOff - 1);

        while (inOff < in.length) {
            in[inOff] = code;
            inOff++;
        }

        return code + 1;
    }

    /**
     * return the number of pad bytes present in the block.
     */
    public int padCount(byte[] in)
            throws InvalidCipherTextException {
        int count = (in[in.length - 1] & 0xff) + 1;
        byte countAsbyte = (byte) (count - 1);

        // constant time version
        boolean failed = (count > in.length | count == 0);

        for (int i = 0; i < in.length; i++) {
            failed |= (in.length - i <= count) & (in[i] != countAsbyte);
        }

        if (failed) {
            throw new InvalidCipherTextException("pad block corrupted");
        }

        return count;
    }
}
