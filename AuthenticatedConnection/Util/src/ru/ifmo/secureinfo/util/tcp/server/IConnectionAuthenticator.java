package ru.ifmo.secureinfo.util.tcp.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * User: danielpenkin
 * Date: May 12, 2010
 */
public interface IConnectionAuthenticator {

    byte[] authenticateConnection(InputStream in, OutputStream out) throws IOException;

}
