package ru.ifmo.secureinfo.srp.stream.server;

import ru.ifmo.secureinfo.srp.*;
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
public class SRPStreamServer {

    private SRPRecordStorage storage;
    private SRPServerLogic logic;

    public SRPStreamServer(SRPRecordStorage storage, String prng, String msgd) throws NoSuchAlgorithmException {
        this.storage = storage;
        logic = new SRPServerLogic();
        logic.setPrng(prng);
        logic.setMsgd(msgd);
    }

    public void setStorage(SRPRecordStorage storage) {
        this.storage = storage;
    }

    public byte[] authenticate(InputStream in, OutputStream out, StreamCoder coder) throws IOException {
        byte[] username = coder.decodeMessage(in);
        String user = new String(username);
        try {
            user = new String(username, "UTF-8");
        } catch (UnsupportedEncodingException ignored) {
        }

        SRPUserRecord userRecord = storage.getUserRecord(user);
        if (userRecord == null) {
            return null;
        }

        SRPServerSession serverSession = new SRPServerSession(logic, userRecord);

        coder.encodeMessage(out, userRecord.getSalt().toByteArray());
        byte[] a = coder.decodeMessage(in);
        coder.encodeMessage(out, serverSession.generateB().toByteArray());

        serverSession.computeSessionKey(new BigInteger(a));

        byte[] userProof = coder.decodeMessage(in);
        if (serverSession.isUserAuthenticated(new BigInteger(userProof))) {
            coder.encodeMessage(out, serverSession.getServerProof().toByteArray());
            return serverSession.getKey().toByteArray();
        } else {
            return null;
        }
    }

    public SRPUserRecord generateRecord(byte[] username, byte[] password) {
        BigInteger salt = logic.randomBigInt();
        BigInteger pair = logic.hash(Common.combine(new BigInteger(username), new BigInteger(password)));
        BigInteger privateKey = logic.hash(Common.combine(logic.randomBigInt(), pair));
        BigInteger verifier = logic.generateVerifier(privateKey);
        return new SRPUserRecord(username, salt, verifier);
    }


}