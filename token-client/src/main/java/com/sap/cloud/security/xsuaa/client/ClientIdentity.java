package com.sap.cloud.security.xsuaa.client;

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

    //TODO impl gethash and equals methods only in client cred
}
