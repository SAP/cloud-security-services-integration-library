package com.sap.cloud.security.xsuaa.client;

import javax.annotation.Nonnull;

/**
 * Deprecated in favor of {@link com.sap.cloud.security.config.ClientCredentials}
 */
@Deprecated
public class ClientCredentials extends com.sap.cloud.security.config.ClientCredentials {
    /**
     * Specifies the OAuth 2.0 client.<br>
     *
     * @param clientId     - the ID of the OAuth 2.0 client requesting the token.
     * @param clientSecret
     */
    public ClientCredentials(@Nonnull String clientId, @Nonnull String clientSecret) {
        super(clientId, clientSecret);
    }
}
