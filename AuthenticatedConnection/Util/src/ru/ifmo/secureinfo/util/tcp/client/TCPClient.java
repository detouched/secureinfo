package ru.ifmo.secureinfo.util.tcp.client;

import ru.ifmo.secureinfo.util.coders.StreamCoder;
import ru.ifmo.secureinfo.util.tcp.server.IConnectionAuthenticator;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.rmi.UnknownHostException;
import java.util.logging.Logger;

/**
 * User: danielpenkin
 * Date: May 11, 2010
 */
public class TCPClient {
    private final Logger log;
    private final StreamCoder coder;

    private Socket socket;

    private InputStream in;
    private OutputStream out;

    private byte[] key;

    public TCPClient(StreamCoder coder, Logger logger) {
        this.coder = coder;
        this.log = logger;
    }

    public boolean connect(String host, int port, IConnectionAuthenticator auth) {
        if (socket != null) {
            log.warning("Requested to connect while not disconnected - skipped");
            return false;
        }

        socket = null;
        try {
            socket = new Socket(host, port);
            in = socket.getInputStream();
            out = socket.getOutputStream();
            log.info("Client connected to " + host + "@" + port);
        } catch (UnknownHostException e) {
            log.severe("Unable to connect to " + host + "@" + port + ": " + e.getMessage());
        } catch (IOException e) {
            log.severe("I/O exception while connecting to host: " + e.getMessage());
        }

        if (socket == null) {
            disconnect();
            return false;
        }

        boolean authenticated = false;

        log.info("Authenticating connection");
        try {
            if (auth.authenticateConnection(in, out) == null) {
                log.info("Connection authentication failed");
            } else {
                authenticated = true;
                log.info("Connection opened");
            }
        } catch (IOException e) {
            log.severe("I/O exception while authenticating: " + e.getMessage());
        }

        if (!authenticated) {
            disconnect();
        }

        return (socket != null);
    }

    public void disconnect() {
        if (socket != null) {
            try {
                in.close();
            } catch (IOException ignored) {
            }
            try {
                out.close();
            } catch (IOException ignored) {
            }
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            log.info("Client disconnected");
        }
        socket = null;
    }


    public byte[] request(byte[] request) throws IOException {
        try {
            coder.encodeMessage(out, request);
        } catch (IOException e) {
            log.severe("I/O excpetion while sending message: " + e.getMessage());
            throw e;
        }

        byte[] rs = null;
        try {
            rs = coder.decodeMessage(in);
        } catch (SocketTimeoutException e) {
            log.finest("Connection timeout");
            throw e;
        } catch (EOFException e) {
            log.finest("Connection was closed on server side");
            throw e;
        } catch (IOException e) {
            log.warning("Unexpected exception while receiving message: " + e.getMessage());
            throw e;
        }

        return rs;
    }
}