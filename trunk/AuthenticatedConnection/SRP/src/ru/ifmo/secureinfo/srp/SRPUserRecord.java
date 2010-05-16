package ru.ifmo.secureinfo.srp;

import java.math.BigInteger;

/**
 * User: danielpenkin
 * Date: May 9, 2010
 */
public class SRPUserRecord {
    private final byte[] username;
    private final BigInteger salt;
    private final BigInteger verifier;

    public SRPUserRecord(byte[] username, BigInteger salt, BigInteger verifier) {
        this.username = username;
        this.salt = salt;
        this.verifier = verifier;
    }

    public byte[] getUsername() {
        return username;
    }

    public BigInteger getSalt() {
        return salt;
    }

    public BigInteger getVerifier() {
        return verifier;
    }
}