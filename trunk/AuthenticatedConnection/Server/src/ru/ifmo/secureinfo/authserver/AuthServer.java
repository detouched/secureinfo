package ru.ifmo.secureinfo.authserver;

import ru.ifmo.secureinfo.srp.SRPUserRecord;
import ru.ifmo.secureinfo.srp.stream.server.SRPStreamServer;
import ru.ifmo.secureinfo.util.coders.StreamCoder;
import ru.ifmo.secureinfo.util.logging.LogFormatter;
import ru.ifmo.secureinfo.util.tcp.server.IConnectionAuthenticator;
import ru.ifmo.secureinfo.util.tcp.server.IRequestProcessor;
import ru.ifmo.secureinfo.util.tcp.server.TCPServer;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * User: danielpenkin
 * Date: May 9, 2010
 */
public class AuthServer implements Runnable, IRequestProcessor, IConnectionAuthenticator {

    private final SRPStreamServer authServer;
    private final UserStorage storage = new UserStorage();
    private final TCPServer tcpServer;
    private final StreamCoder coder;
    private final Logger log;

    public AuthServer(Logger log) throws NoSuchAlgorithmException {
        this.log = log;
        authServer = new SRPStreamServer(storage, "SHA1PRNG", "SHA");
        authServer.setStorage(storage);
        coder = new StreamCoder(log);
        tcpServer = new TCPServer(log, coder);
        tcpServer.setRequestProcessor(this, this);
    }

    public byte[] authenticateConnection(InputStream in, OutputStream out) throws IOException {
        return authServer.authenticate(in, out, coder);
    }

    public byte[] processRequest(byte[] request, byte[] key) {
        log.info("Hooray: request with key");
        return new byte[]{(byte) 45, (byte) 45};
        //TODO what should be next?
    }

    private void processAdd(String cmd) {
        String[] part = cmd.split(" ");
        if (part.length == 3) {
            byte[] username = part[1].getBytes();
            try {
                username = part[1].getBytes("UTF-8");
            } catch (UnsupportedEncodingException ignored) {
            }
            byte[] password = part[2].getBytes();
            try {
                password = part[2].getBytes("UTF-8");
            } catch (UnsupportedEncodingException ignored) {
            }
            SRPUserRecord record = authServer.generateRecord(username, password);
            storage.addUserRecord(part[1], record);
            System.out.println("User " + part[1] + " added");
        } else {
            System.out.println("ADD syntax: add <username> <password>");
        }
    }

    private void processRemove(String cmd) {
        String[] part = cmd.split(" ");
        if (part.length == 2) {
            if (storage.removeUserRecord(part[1]) != null) {
                System.out.println("User " + part[1] + " removed");
            } else {
                System.out.println("No user " + part[1] + " registered");
            }
        } else {
            System.out.println("REMOVE syntax: remove <username>");
        }
    }

    private void processStart(String cmd) {
        String[] part = cmd.split(" ");
        if (part.length == 2) {
            try {
                int port = Integer.parseInt(part[1]);
                if (tcpServer.start(port)) {
                    System.out.print("Starting server at port " + port + ".....");
                    while ((tcpServer.getStatus() != TCPServer.Status.UP) &&
                            (tcpServer.getStatus() != TCPServer.Status.CRASHED)) {
                        try {
                            Thread.sleep(100);
                        } catch (InterruptedException ignored) {
                        }
                    }
                    if (tcpServer.getStatus() == TCPServer.Status.UP) {
                        System.out.println("OK");
                    } else {
                        System.out.println("FAIL");
                    }
                }
            } catch (NumberFormatException e) {
                System.out.println("Port is not a number");
            }

        } else {
            System.out.println("START syntax: start <port>");
        }
    }

    private void processStop() {
        System.out.print("Stopping server...");
        tcpServer.stop();
        while (tcpServer.getStatus() != TCPServer.Status.DOWN) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
            }
        }
        System.out.println("OK");
    }

    private void processSave(String cmd) {
        String[] part = cmd.split(" ");
        if ((part.length == 2) || (part.length == 3)) {
            File file = new File(part[1]);
            boolean append = false;
            if (part.length == 3) {
                append = Boolean.parseBoolean(part[2]);
            }
            try {
                storage.saveToFile(file, append);
                System.out.println("Storage saved to file");
            } catch (IOException e) {
                System.out.println("Failed to save: " + e.getMessage());
            }
        } else {
            System.out.println("SAVE syntax: save <filepath> [<append:false>]");
        }
    }

    private void processLoad(String cmd) {
        String[] part = cmd.split(" ");
        if ((part.length == 2) || (part.length == 3)) {
            File file = new File(part[1]);
            boolean append = false;
            if (part.length == 3) {
                append = Boolean.parseBoolean(part[2]);
            }
            try {
                storage.loadFromFile(file, append);
                System.out.println("Storage loaded from file");
            } catch (IOException e) {
                System.out.println("Failed to load: " + e.getMessage());
            }
        } else {
            System.out.println("LOAD syntax: load <filepath> [<append:false>]");
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
                    if (lc.startsWith("add")) {
                        processAdd(cmd);
                    } else if (lc.startsWith("remove")) {
                        processRemove(cmd);
                    } else if (lc.startsWith("start")) {
                        processStart(cmd);
                    } else if (lc.startsWith("stop")) {
                        processStop();
                    } else if (lc.startsWith("save")) {
                        processSave(cmd);
                    } else if (lc.startsWith("load")) {
                        processLoad(cmd);
                    }
                }
            } catch (IOException ignored) {
            }

        } while ((cmd != null) && (!cmd.startsWith("exit")));
        System.out.println("Exiting");
        tcpServer.stop();
        while (tcpServer.getStatus() != TCPServer.Status.DOWN) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
            }
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Logger log = Logger.getLogger("authlog");
        log.setLevel(Level.ALL);
        try {
            Handler h = new FileHandler("as_%u.log", 1048576, 1, false);
            h.setFormatter(new LogFormatter());
            log.addHandler(h);
        } catch (IOException e) {
            System.out.println("Unable to create logs");
        }

        new AuthServer(log).run();
    }
}