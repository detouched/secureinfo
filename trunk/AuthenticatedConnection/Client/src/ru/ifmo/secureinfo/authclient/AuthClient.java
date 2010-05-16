package ru.ifmo.secureinfo.authclient;

import ru.ifmo.secureinfo.srp.stream.client.SRPStreamClient;
import ru.ifmo.secureinfo.util.coders.StreamCoder;
import ru.ifmo.secureinfo.util.logging.LogFormatter;
import ru.ifmo.secureinfo.util.tcp.client.TCPClient;
import ru.ifmo.secureinfo.util.tcp.server.IConnectionAuthenticator;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * User: danielpenkin
 * Date: May 12, 2010
 */
public class AuthClient implements Runnable, IConnectionAuthenticator {
    private static String PRNG = "SHA1PRNG";
    private static String MSGD = "SHA";

    private final TCPClient tcpClient;
    private final StreamCoder coder;
    private final Logger log;

    private SRPStreamClient authClient;
    private byte[] key;

    public AuthClient(Logger log) {
        this.log = log;
        coder = new StreamCoder(log);
        tcpClient = new TCPClient(coder, log);
    }

    public byte[] authenticateConnection(InputStream in, OutputStream out) throws IOException {
        if (authClient != null) {
            key = authClient.authenticate(in, out, coder);
            return key;
        }
        return null;
    }

    private void processConnect(String cmd) {
        String[] part = cmd.split(" ");
        if (part.length == 5) {
            try {
                authClient = new SRPStreamClient(PRNG, MSGD, part[3], part[4]);
                try {
                    int port = Integer.parseInt(part[2]);
                    tcpClient.connect(part[1], port, this);
                } catch (NumberFormatException e) {
                    System.out.println("Port is not a number");
                }
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Failed to connect: " + e.getMessage());
            }
        } else {
            System.out.println("CONNECT syntax: connect <host> <port> <username> <password>");
        }
    }

    private void processDisconnect() {
        tcpClient.disconnect();
        authClient = null;
        key = null;
    }

    private void processSend(String cmd) {
        String[] part = cmd.split(" ");
        if (part.length == 2) {
            byte[] rq = part[1].getBytes();
            try {
                rq = part[1].getBytes("UTF-8");
            } catch (UnsupportedEncodingException ignored) {
            }
            byte[] rs = new byte[0];
            try {
                rs = tcpClient.request(rq);
            } catch (IOException e) {
                System.out.println("Failed to request server: " + e.getMessage());
            }
            String response = new String(rs);
            try {
                response = new String(rs, "UTF-8");
            } catch (UnsupportedEncodingException ignored) {
            }
            System.out.println("Server response: " + response);
        } else {
            System.out.println("SEND syntax: send <text>");
        }
    }

    public void run() {
        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
        String cmd = null;
        do {
            try {
                cmd = console.readLine();
                if (cmd != null) {
                    cmd = cmd.trim();
                    String lc = cmd.toLowerCase();
                    if (lc.startsWith("connect")) {
                        processConnect(cmd);
                    } else if (lc.startsWith("disconnect")) {
                        processDisconnect();
                    } else if (lc.startsWith("send")) {
                        processSend(cmd);
                    }
//                    } else if (lc.startsWith("stop")) {
//                        processStop();
//                    } else if (lc.startsWith("save")) {
//                        processSave(cmd);
//                    } else if (lc.startsWith("load")) {
//                        processLoad(cmd);
//                    }
                }
            } catch (IOException ignored) {
            }

        } while ((cmd != null) && (!cmd.startsWith("exit")));
        System.out.println("Exiting");
        tcpClient.disconnect();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Logger log = Logger.getLogger("authlog");
        log.setLevel(Level.ALL);
        try {
            Handler h = new FileHandler("ac_%u.log", 1048576, 1, false);
            h.setFormatter(new LogFormatter());
            log.addHandler(h);
        } catch (IOException e) {
            System.out.println("Unable to create logs");
        }

        new AuthClient(log).run();
    }

}