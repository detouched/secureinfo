package ru.ifmo.secureinfo.srp;

import java.math.BigInteger;

/**
 * User: danielpenkin
 * Date: May 10, 2010
 */
public class SRPClientSession {
    private final BigInteger aRandom;
    private final byte[] username;
    private final byte[] password;
    private SRPClientLogic logic;
    private BigInteger A = null;
    private BigInteger B = null;
    private BigInteger K = null;
    private BigInteger salt = null;
    private BigInteger proof = null;

    public SRPClientSession(SRPClientLogic client, byte[] username, byte[] password) {
        logic = client;
        aRandom = logic.randomBigInt();
        this.username = new byte[username.length];
        System.arraycopy(username, 0, this.username, 0, this.username.length);
        this.password = new byte[password.length];
        System.arraycopy(password, 0, this.password, 0, this.password.length);
    }

    public BigInteger generateA() {
        if (A != null) {
            throw new IllegalStateException("A has already been computed");
        }
        A = logic.generateA(aRandom);
        return new BigInteger(A.toByteArray());
    }

    public BigInteger computeSessionKey(BigInteger salt, BigInteger B) {
        if (A == null) {
            throw new IllegalStateException("A hadn't been computed yet");
        }
        if (K != null) {
            throw new IllegalStateException("Key has already been computed");
        }
        this.salt = new BigInteger(salt.toByteArray());
        this.B = new BigInteger(B.toByteArray());
        BigInteger privateKey = logic.generatePrivateKeyX(password, this.salt);
        K = logic.computeSessionKeyK(A, this.B, privateKey, aRandom);
        return new BigInteger(K.toByteArray());
    }

    public BigInteger getProof() {
        if (K == null) {
            throw new IllegalStateException("Key hadn't been computed yet");
        }
        if (proof == null) {
            proof = logic.generateProof(username, salt, A, B, K);
        }
        return proof;
    }

    public boolean isServerAuthenticated(BigInteger serverProof) {
        if (proof == null) {
            throw new IllegalStateException("Server hadn't been requested to authenticate");
        }
        BigInteger myProof;
        myProof = logic.generateSecondaryProof(A, proof, K);
        return myProof.equals(serverProof);
    }

    public BigInteger getKey() {
        if (K != null) {
            return new BigInteger(K.toByteArray());
        }
        return null;
    }

}