package ru.ifmo.secureinfo.util.tcp.server;

/**
 * User: danielpenkin
 * Date: May 11, 2010
 */
public interface IRequestProcessor extends IConnectionAuthenticator {

    byte[] processRequest(byte[] request, byte[] key);
}
