package ru.ifmo.secureinfo.srp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * User: danielpenkin
 * Date: May 9, 2010
 */
/*package-private*/ abstract class SRPBase {

    private static BigInteger TWO = BigInteger.valueOf(2);

    protected SecureRandom prng = null;
    protected MessageDigest msgd = null;
    protected SRPConst constants = new SRPConst();

    private BigInteger multiplierK = null;

    public void setPrng(String prng) throws NoSuchAlgorithmException {
        this.prng = SecureRandom.getInstance(prng);
    }

    public void setMsgd(String msgd) throws NoSuchAlgorithmException {
        this.msgd = MessageDigest.getInstance(msgd);
    }

    public boolean isPRNGandMSGDset() {
        return ((prng != null) && (msgd != null));
    }

    public BigInteger generateScrambleU(BigInteger A, BigInteger B) {
        return hash(Common.combine(A, B));
    }

    public BigInteger getMultiplierK() {
        if (multiplierK == null) {
            multiplierK = hash(Common.combine(constants.getPrime(), constants.getGenerator()));
        }
        return new BigInteger(multiplierK.toByteArray());
    }

    public BigInteger randomBigInt() {
        int numberOfBytes = (2 * constants.getPrime().bitLength() - 1) / 8;
        byte[] b = new byte[numberOfBytes];
        prng.nextBytes(b);
        BigInteger i = new BigInteger(b);

        // random numbers must satisfy: 1 < random < n
        BigInteger max = constants.getPrime().subtract(TWO);
        return i.mod(max).add(TWO);
    }

    public BigInteger hash(BigInteger i) {
        byte[] b = i.toByteArray();
        msgd.update(b, 0, b.length);
        byte[] digest = msgd.digest();
        return new BigInteger(digest);
    }

    public BigInteger generateProof(byte[] username, BigInteger salt, BigInteger A, BigInteger B, BigInteger keyK) {
        // PROOF = H(H(N) xor H(g), H(I), s, A, B, K)
        BigInteger nXorG = hash(constants.getPrime()).xor(hash(constants.getGenerator()));
        BigInteger ngi = Common.combine(nXorG, hash(new BigInteger(username)));
        BigInteger ngisA = Common.combine(Common.combine(ngi, salt), A);
        BigInteger bgisABK = Common.combine(Common.combine(ngisA, B), keyK);
        return hash(bgisABK);
    }

    public BigInteger generateSecondaryProof(BigInteger A, BigInteger proofM, BigInteger keyK) {
        // PROOF = H(A, M, K)
        BigInteger AMK = Common.combine(Common.combine(A, proofM), keyK);
        return hash(AMK);
    }
}