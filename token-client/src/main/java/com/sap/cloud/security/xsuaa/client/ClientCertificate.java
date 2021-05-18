package com.sap.cloud.security.xsuaa.client;

public class ClientCertificate implements ClientIdentity{

    private final String certificate;
    private final String key;
    private final String clientId;

    public ClientCertificate(String certificate, String key, String clientId) {
        this.certificate = certificate;
        this.key = key;
        this.clientId = clientId;
    }

    @Override
    public String getCertificate() {
        return certificate;
    }

    @Override
    public String getKey() {
        return key;
    }

    @Override
    public String getId() {
        return clientId;
    }

    @Override
    public boolean isValid() {
        return clientId != null && certificate != null && key != null;
    }

    @Override
    public boolean isCertificateBased() {
        return true;
    }
}
