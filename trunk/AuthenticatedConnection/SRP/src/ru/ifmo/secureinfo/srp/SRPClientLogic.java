package ru.ifmo.secureinfo.srp;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * User: danielpenkin
 * Date: May 9, 2010
 */
public class SRPClientLogic extends SRPBase {

    private Logger log = Logger.getLogger("authlog");

    public BigInteger generateA(BigInteger randa) {
        // TODO check A
        // A = g^a, a = random()
        BigInteger A = constants.getGenerator().modPow(randa, constants.getPrime());
        log.fine("Computed A: " + A + " based on a: " + randa);
        return A;
    }

    public BigInteger generatePrivateKeyX(byte[] password, BigInteger salt) {
        // x = H(s, p)
        BigInteger pass = new BigInteger(password);
        BigInteger x = hash(Common.combine(pass, salt));
        log.fine("Computed x: " + x + " based on password: " + pass + " and salt: " + salt);
        return x;
    }

    public BigInteger computeSessionKeyK(BigInteger A, BigInteger B, BigInteger privateKeyX, BigInteger randa) {
        // S = (B - kg^x) ^ (a + ux)
        BigInteger scrambleU = generateScrambleU(A, B);
        log.fine("Computed u: " + scrambleU + " based on A: " + A + " and B: " + B);
        //TODO check scramble
        BigInteger power = randa.add(scrambleU.multiply(privateKeyX));
        BigInteger gPowX = constants.getGenerator().modPow(privateKeyX, constants.getPrime());
        BigInteger base = B.subtract(getMultiplierK().multiply(gPowX));
        BigInteger S = base.modPow(power, constants.getPrime());
        log.fine("Computed S: " + S);
        //TODO .mod(constants.getPrime()) up there?

        // K = H(S)
        BigInteger K = hash(S);
        log.fine("Computed K: " + K);
        return K;
    }

}