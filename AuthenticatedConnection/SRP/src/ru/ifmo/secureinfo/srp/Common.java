package ru.ifmo.secureinfo.srp;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * User: danielpenkin
 * Date: May 9, 2010
 */
public class Common {

    /**
     * Combine two integers into one. This method uses a novel combining method rather than simple concatenation. My assumption is
     * that it will add an additional level of security as a malicious party would not be able to guess this method. The bytes from
     * each value are interleaved in pairs. If the first value of the pair is odd, two bytes are taken from the second value. Any
     * remaining bytes are appended at the end.
     *
     * @param a first value to combine
     * @param b second value to combine
     * @return combined value
     */
    public static BigInteger combine(BigInteger a, BigInteger b) {
        ByteBuffer aBuf = ByteBuffer.wrap(a.toByteArray());
        ByteBuffer bBuf = ByteBuffer.wrap(b.toByteArray());
        byte[] combined = new byte[aBuf.capacity() + bBuf.capacity()];
        ByteBuffer combinedBuf = ByteBuffer.wrap(combined);

        aBuf.rewind();
        bBuf.rewind();
        combinedBuf.clear();

        while (aBuf.hasRemaining() && bBuf.hasRemaining()) {
            byte aByte = aBuf.get();
            combinedBuf.put(aByte);
            byte bByte = bBuf.get();
            combinedBuf.put(bByte);
            if (((aByte & 1) == 0) && bBuf.hasRemaining()) {
                bByte = bBuf.get();
                combinedBuf.put(bByte);
            }
        }

        while (aBuf.hasRemaining()) {
            byte x = aBuf.get();
            combinedBuf.put(x);
        }

        while (bBuf.hasRemaining()) {
            byte x = bBuf.get();
            combinedBuf.put(x);
        }

        return new BigInteger(combined);
    }
}