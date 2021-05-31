package com.sap.cloud.security.config;

/**
 * Constants denoting the credential types of a xsuaa OAuth2 configuration
 */
public enum CredentialType {
    X509("x509"),
    INSTANCE_SECRET("instance-secret"),
    BINDING_SECRET("binding-secret");

    private final String typeName;

    CredentialType(String typeName) {
        this.typeName = typeName;
    }

    @Override
    public String toString() {
        return typeName;
    }

}
