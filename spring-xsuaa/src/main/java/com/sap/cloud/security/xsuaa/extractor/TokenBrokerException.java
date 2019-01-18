package com.sap.cloud.security.xsuaa.extractor;

public class TokenBrokerException extends Exception {

    private static final long serialVersionUID = 1L;

    public TokenBrokerException(String message, Exception e) {
        super(message, e);
    }

    public TokenBrokerException(String message) {
        super(message);
    }

}