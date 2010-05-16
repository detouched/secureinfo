package ru.ifmo.secureinfo.srp;

import java.math.BigInteger;

/**
 * User: danielpenkin
 * Date: May 9, 2010
 */
public class SRPConst {

    private final BigInteger prime;
    private final BigInteger generator;

    public SRPConst() {
        prime = new BigInteger("115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3", 16);
        generator = new BigInteger("2");
    }

    public SRPConst(BigInteger prime, BigInteger generator) {
        this.prime = prime;
        this.generator = generator;
    }

    public BigInteger getPrime() {
        return prime;
    }

    public BigInteger getGenerator() {
        return generator;
    }
}