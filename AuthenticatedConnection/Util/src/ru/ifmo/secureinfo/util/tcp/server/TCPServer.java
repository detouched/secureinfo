package ru.ifmo.secureinfo.util.tcp.server;

import ru.ifmo.secureinfo.util.coders.StreamCoder;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * User: danielpenkin
 * Date: May 11, 2010
 */
public class TCPServer implements IConnectionManager {
    private final Logger log;
    private final StreamCoder coder;
    private final Map<TCPConnection, Thread> connections = new HashMap<TCPConnection, Thread>();

    public enum Status {
        UP, DOWN, STARTING, STOPPING, CRASHED
    }

    private int serverSocketTimeout = 10000;
    private int socketTimeout = 10000;
    private int connectionLimit = 10;
    private boolean need2stop;
    private Status status = Status.DOWN;

    private IRequestProcessor proc;
    private IConnectionAuthenticator auth;

    private ServerThread server;

    public TCPServer(Logger logger, StreamCoder coder) {
        this.log = logger;
        this.coder = coder;
    }

    public void setServerSocketTimeout(int serverSocketTimeout) {
        this.serverSocketTimeout = serverSocketTimeout;
    }

    public void setSocketTimeout(int socketTimeout) {
        this.socketTimeout = socketTimeout;
    }

    public void setConnectionLimit(int connectionLimit) {
        this.connectionLimit = connectionLimit;
    }

    public void setRequestProcessor(IRequestProcessor processor, IConnectionAuthenticator authenticator) {
        this.proc = processor;
        this.auth = authenticator;
    }

    public Status getStatus() {
        return status;
    }

    public void connectionClosed(TCPConnection connection) {
        synchronized (connections) {
            connections.remove(connection);
        }
    }

    public synchronized boolean start(int port) {
        if ((status != Status.DOWN) && (status != Status.CRASHED)) {
            log.warning("Start requested while server is working - skipped");
            return false;
        }
        if ((proc != null) && (port > 0)) {
            log.info("Server requested to start");
            need2stop = false;
            server = new ServerThread(port);
            Thread thread = new Thread(server);
            thread.start();
            return true;
        }
        log.severe("Can't start server: " +
                ((port > 0) ? "message processor undefined" : "incorrect port defined"));
        return false;
    }

    public synchronized void stop() {
        if (status == Status.UP) {
            log.info("Server requested to stop");
            need2stop = true;
        } else if (status == Status.CRASHED) {
            status = Status.DOWN;
            log.info("Server status reset");
        }
    }

    private class ServerThread implements Runnable {
        private final int port;
        private ServerSocket serverSocket;

        private ServerThread(int port) {
            this.port = port;
        }

        public void run() {
            status = Status.STARTING;
            log.info("Starting TCP server listening port " + port);
            try {
                // binding port and setting timeout
                serverSocket = new ServerSocket(port);
                serverSocket.setSoTimeout(serverSocketTimeout);
            } catch (SocketException e) {
                status = Status.CRASHED;
                log.severe("Unable to set timeout: " + e.getMessage());
            } catch (IOException e) {
                status = Status.CRASHED;
                log.severe("Unable to bind port: " + e.getMessage());
            }

            if (status == Status.CRASHED) {
                return;
            }

            status = Status.UP;
            log.info("TCP server started");

            while (!need2stop) {
                Socket socket = null;
                try {
                    log.fine("Waiting for client for " + serverSocketTimeout + " ms");
                    socket = serverSocket.accept();
                    log.finer("Connection accepted");
                } catch (IOException e) {
                    log.fine("No connection established");
                }

                if (socket != null) {
                    TCPConnection conn = new TCPConnection(socket, log, coder, TCPServer.this, proc, auth);
                    Thread connThread = new Thread(conn);
                    connections.put(conn, connThread);
                    connThread.start();
                }
            }

            status = Status.STOPPING;
            log.info("Stopping TCP server");

            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }

            synchronized (connections) {
                for (TCPConnection conn : connections.keySet()) {
                    conn.stop();
                }
            }

            log.finest("Waiting for all connections to close");

            while (connections.size() > 0) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {
                }
            }

            status = Status.DOWN;
            log.info("TCP server stopped");
        }
    }

}