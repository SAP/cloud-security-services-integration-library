package com.sap.cloud.security.xsuaa.client;

import javax.annotation.Nonnull;

import java.util.Objects;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

public class ClientCertificate implements ClientIdentity{

    private final String certificate;
    private final String key;
    private final String clientId;

    public ClientCertificate(@Nonnull String certificate, @Nonnull String key, @Nonnull String clientId) {
            assertNotNull(clientId, "clientId is required");
            assertNotNull(certificate, "certificate is required");
            assertNotNull(key, "RSA Private key is required");

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
        return !clientId.isEmpty() && !certificate.isEmpty() && !key.isEmpty();
    }

    @Override
    public boolean isCertificateBased() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ClientCertificate)) return false;
        ClientCertificate that = (ClientCertificate) o;
        return certificate.equals(that.certificate) &&
                key.equals(that.key) &&
                clientId.equals(that.clientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(certificate, key, clientId);
    }
}
