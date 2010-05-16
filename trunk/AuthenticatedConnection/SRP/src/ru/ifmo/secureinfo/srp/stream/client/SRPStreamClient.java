package ru.ifmo.secureinfo.srp.stream.client;

import ru.ifmo.secureinfo.srp.SRPClientLogic;
import ru.ifmo.secureinfo.srp.SRPClientSession;
import ru.ifmo.secureinfo.util.coders.StreamCoder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

/**
 * User: danielpenkin
 * Date: May 10, 2010
 */
public class SRPStreamClient {

    private final SRPClientSession clientSession;
    private byte[] user;

    public SRPStreamClient(String prng, String msgd, String username, String password) throws NoSuchAlgorithmException {
        SRPClientLogic logic = new SRPClientLogic();
        logic.setPrng(prng);
        logic.setMsgd(msgd);

        byte[] pass;
        try {
            user = username.getBytes("UTF-8");
            pass = password.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            user = username.getBytes();
            pass = password.getBytes();
        }
        clientSession = new SRPClientSession(logic, user, pass);
    }

    public byte[] authenticate(InputStream in, OutputStream out, StreamCoder coder) throws IOException {
        coder.encodeMessage(out, user);
        byte[] salt = coder.decodeMessage(in);
        coder.encodeMessage(out, clientSession.generateA().toByteArray());
        byte[] b = coder.decodeMessage(in);
        coder.encodeMessage(out, computeProof(salt, b));
        byte[] serverProof = coder.decodeMessage(in);
        return getKeyIfAuthenticated(serverProof);
    }

    public byte[] computeProof(byte[] salt, byte[] b) throws IOException {
        clientSession.computeSessionKey(new BigInteger(salt), new BigInteger(b));
        return clientSession.getProof().toByteArray();
    }

    public byte[] getKeyIfAuthenticated(byte[] serverProof) throws IOException {
        if (clientSession.isServerAuthenticated(new BigInteger(serverProof))) {
            return clientSession.getKey().toByteArray();
        } else {
            return null;
        }
    }

}