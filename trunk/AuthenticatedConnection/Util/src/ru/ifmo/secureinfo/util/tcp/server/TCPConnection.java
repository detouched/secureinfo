package ru.ifmo.secureinfo.util.tcp.server;

import ru.ifmo.secureinfo.util.coders.HEXCoder;
import ru.ifmo.secureinfo.util.coders.StreamCoder;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.logging.Logger;

/**
 * User: danielpenkin
 * Date: May 11, 2010
 */
/*package-private*/ class TCPConnection implements Runnable {

    private final Socket socket;
    private final Logger log;
    private final StreamCoder coder;
    private final IRequestProcessor proc;
    private final IConnectionAuthenticator auth;
    private final IConnectionManager man;

    private InputStream in;
    private OutputStream out;

    private boolean need2stop = false;

    private byte[] key;

    TCPConnection(Socket socket, Logger log, StreamCoder coder, IConnectionManager manager,
                  IRequestProcessor processor, IConnectionAuthenticator auth) {
        this.socket = socket;
        this.log = log;
        this.coder = coder;
        this.proc = processor;
        this.man = manager;
        this.auth = auth;
    }

    public void run() {
        log.info("Opening connection with " + socket.getRemoteSocketAddress());

        try {
            in = socket.getInputStream();
            out = socket.getOutputStream();
        } catch (IOException e) {
            log.severe("Stream mapping failed: " + e.getMessage());
            need2stop = true;
        }


        log.info("Authenticating connection");
        try {
            if ((key = auth.authenticateConnection(in, out)) == null) {
                log.info("Connection authentication failed");
                need2stop = true;
            }
        } catch (IOException e) {
            log.severe("I/O exception while authenticating: " + e.getMessage());
            need2stop = true;
        }
        log.info("Connection opened");

        while (!need2stop) {
            try {
                byte[] rq = coder.decodeMessage(in);
                log.finer("Message received: " + HEXCoder.bytes2hex(rq));
                coder.encodeMessage(out, proc.processRequest(rq, key));
            } catch (SocketTimeoutException e) {
                log.finest("Connection timeout");
                need2stop = true;
            } catch (EOFException e) {
                log.finest("Connection was closed on client side");
                need2stop = true;
            } catch (IOException e) {
                log.warning("Unexpected exception: " + e.getMessage());
                need2stop = true;
            }
        }

        log.info("Closing connection");
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

        man.connectionClosed(this);

        log.info("Connection closed");

    }

    public void stop() {
        log.info("Connection requested to stop");
        need2stop = true;
    }

}