package com.sap.xsa.security.container;

/**
 * Represents xsuaa client identity
 */
public interface ClientIdentity {
    String getId();

    default boolean isValid() {
        return true;
    }

    default boolean isCertificateBased() {
        return false;
    }

    default String getSecret() {
        return null;
    }

    default String getCertificate(){
        return null;
    }

    default String getKey(){
        return null;
    }

}
