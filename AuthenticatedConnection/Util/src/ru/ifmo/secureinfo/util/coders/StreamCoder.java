package ru.ifmo.secureinfo.util.coders;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Logger;

/**
 * User: danielpenkin
 * Date: May 9, 2010
 */
public class StreamCoder {

    public static String EOS = "End of stream reached";

    private final Logger log;

    public StreamCoder(Logger log) {
        this.log = log;
    }

    public void encodeStringMessage(OutputStream out, String message) throws IOException {
        log.fine("Encoding string message: " + message);
        byte[] bMessage = message.getBytes("UTF-8");
        encodeMessage(out, bMessage);
    }

    public String decodeStringMessage(InputStream in) throws IOException {
        byte[] bMessage = decodeMessage(in);
        String message = new String(bMessage, "UTF-8");
        log.fine("String message read: " + message);
        return message;
    }

    public void encodeMessage(OutputStream out, byte[] message) throws IOException {
        log.fine("Encoding message: " + HEXCoder.bytes2hex(message));

        // calculate header size
        int length = message.length;
        byte headerSize;
        if (length <= Byte.MAX_VALUE) {
            headerSize = 1;
        } else if (length <= Short.MAX_VALUE) {
            headerSize = 2;
        } else {
            headerSize = 4;
        }
        log.fine("Message length: " + length + "; header length: " + headerSize);

        // fill header
        byte[] header = new byte[headerSize];
        for (int i = 0; i < headerSize; i++) {
            // write length of message in array of bytes, big-endian way
            header[headerSize - i - 1] = (byte) (length >> (8 * i));
        }

        // write headerSize, header and message to stream
        out.write(headerSize);
        out.write(header);
        out.write(message);

        log.fine("Message written to stream");
    }

    public byte[] decodeMessage(InputStream in) throws IOException {
        log.fine("Reading message");
        // read header size
        byte headerSize = (byte) in.read();
        if (headerSize < 0) {
            log.severe("Failed to read header size: EOS reached");
            throw new IOException(EOS);
        }
        log.fine("Header length: " + headerSize);

        // read header
        byte[] header = new byte[headerSize];
        int readFromIn;
        readFromIn = in.read(header);
        if (readFromIn != header.length) {
            log.severe("Failed to read header: EOS reached");
            throw new IOException(EOS);
        }

        int length = 0;
        for (byte b : header) {
            length = (length << 8) | b;
        }
        log.fine("Message length: " + length);

        byte[] message = new byte[length];
        readFromIn = in.read(message);
        if (readFromIn != message.length) {
            log.severe("Failed to read message body: EOS reached");
            throw new IOException(EOS);
        }
        log.fine("Message read: " + HEXCoder.bytes2hex(message));

        return message;
    }


}