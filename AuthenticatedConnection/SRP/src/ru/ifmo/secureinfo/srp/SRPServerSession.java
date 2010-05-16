package ru.ifmo.secureinfo.srp;

import java.math.BigInteger;

/**
 * User: danielpenkin
 * Date: May 10, 2010
 */
public class SRPServerSession {
    private final SRPUserRecord record;
    private final BigInteger bRandom;
    private SRPServerLogic logic;
    private BigInteger A = null;
    private BigInteger B = null;
    private BigInteger K = null;
    private BigInteger proof = null;

    public SRPServerSession(SRPServerLogic logic, SRPUserRecord record) {
        this.record = record;
        this.logic = logic;
        bRandom = this.logic.randomBigInt();
    }

    public BigInteger generateB() {
        if (B != null) {
            throw new IllegalStateException("B has already been computed");
        }
        B = logic.generateB(record.getVerifier(), bRandom);
        return new BigInteger(B.toByteArray());
    }

    public BigInteger computeSessionKey(BigInteger A) {
        if (B == null) {
            throw new IllegalStateException("B hadn't been computed yet");
        }
        if (K != null) {
            throw new IllegalStateException("Key has already been computed");
        }
        this.A = new BigInteger(A.toByteArray());
        K = logic.computeSessionKeyK(this.A, B, record.getVerifier(), bRandom);
        return new BigInteger(K.toByteArray());
    }

    public boolean isUserAuthenticated(BigInteger userProof) {
        if (K == null) {
            throw new IllegalStateException("Key hadn't been computed yet");
        }
        BigInteger myProof;
        myProof = logic.generateProof(record.getUsername(), record.getSalt(), A, B, K);
        if (myProof.equals(userProof)) {
            proof = logic.generateSecondaryProof(A, userProof, K);
        }
        return (proof != null);
    }

    public BigInteger getServerProof() {
        if (proof != null) {
            return new BigInteger(proof.toByteArray());
        }
        return null;
    }

    public BigInteger getKey() {
        if (K != null) {
            return new BigInteger(K.toByteArray());
        }
        return null;
    }
}