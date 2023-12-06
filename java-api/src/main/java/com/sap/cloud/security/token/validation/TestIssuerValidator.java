package com.sap.cloud.security.token.validation;

/**
 * This interface is for INTERNAL usage only to add backward-compatibility for test credentials with trusted domain 'localhost' to the issuer validation.
 */
public interface TestIssuerValidator {
    boolean isValidIssuer(String issuer);
}