package ru.ifmo.secureinfo.util.tcp.server;

/**
 * User: danielpenkin
 * Date: May 11, 2010
 */
/*package-private*/ interface IConnectionManager {
    void connectionClosed(TCPConnection connection);
}
