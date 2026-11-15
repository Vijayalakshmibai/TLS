package com.tlsmonitor.common.exception;

public class SSRFSecurityException extends RuntimeException {
    public SSRFSecurityException(String message) {
        super(message);
    }
}
