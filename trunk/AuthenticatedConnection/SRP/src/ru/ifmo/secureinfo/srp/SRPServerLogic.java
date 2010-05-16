package ru.ifmo.secureinfo.srp;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * User: danielpenkin
 * Date: May 9, 2010
 */
public class SRPServerLogic extends SRPBase {

    private Logger log = Logger.getLogger("authlog");

    public BigInteger generateB(BigInteger verifierV, BigInteger randb) {
        // TODO check B
        // B = kv + g^b, b = random()
        BigInteger B = verifierV.multiply(getMultiplierK()).add(constants.getGenerator().modPow(randb, constants.getPrime()));
        log.fine("Computed B: " + B + " based on verifier: " + verifierV + " and b: " + randb);
        return B;
    }

    public BigInteger computeSessionKeyK(BigInteger A, BigInteger B, BigInteger verifierV, BigInteger randb) {
        // S = (Av^u) ^ b
        BigInteger scrambleU = generateScrambleU(A, B);
        log.fine("Computed u: " + scrambleU + " based on A: " + A + " and B: " + B);
        //TODO check scramble
        BigInteger vModPowU = verifierV.modPow(scrambleU, constants.getPrime());
        BigInteger base = A.multiply(vModPowU);
        BigInteger S = base.modPow(randb, constants.getPrime());
        log.fine("Computed S: " + S);

        // K = H(S)
        BigInteger K = hash(S);
        log.fine("Computed K: " + K);
        return K;
    }

    public BigInteger generateVerifier(BigInteger privateKey) {
        BigInteger v = constants.getGenerator().modPow(privateKey, constants.getPrime());
        log.fine("Computed v: " + v + " based on private key: " + privateKey);
        return v;
    }

}