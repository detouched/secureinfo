package ru.ifmo.secureinfo.srp.stream;

/**
 * User: danielpenkin
 * Date: May 10, 2010
 */
public class AuthenticationFailedException extends Exception {
    public AuthenticationFailedException(String message) {
        super(message);
    }
}