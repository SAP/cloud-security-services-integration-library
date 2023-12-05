package com.sap.cloud.security.token.validation;

/**
 * LocalhostIssuerValidator brings backward-compatibility for test credentials in consumer applications written before 2.17.0 that are used to validate java-security-test tokens.
 * This is necessary for successful validation of localhost issuers that include a port when 'localhost' is defined as trusted domain without port in the service credentials.
 * This class MUST NOT be loaded outside test scope and MUST be the ONLY implementation of {@link TestIssuerValidator}.
 */
public class LocalhostIssuerValidator implements TestIssuerValidator {

    @Override
    public boolean isValidIssuer(String issuer) {
        return issuer.startsWith("http://localhost") || issuer.startsWith("https://localhost");
    }
}
