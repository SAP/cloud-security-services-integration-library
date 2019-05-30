package com.sap.cloud.security.xsuaa.tokenflows;

/**
 * Exception thrown to signal issues during a token flow execution.
 */
public class TokenFlowException extends Exception {
    private static final long serialVersionUID = 1452898292676860358L;

    /**
     * @see Exception.
     */
    public TokenFlowException() {
        super();
    }

    /**
     * @see Exception.
     */
    public TokenFlowException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    /**
     * @see Exception.
     */
    public TokenFlowException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @see Exception.
     */
    public TokenFlowException(String message) {
        super(message);
    }

    /**
     * @see Exception.
     */
    public TokenFlowException(Throwable cause) {
        super(cause);
    }
}
