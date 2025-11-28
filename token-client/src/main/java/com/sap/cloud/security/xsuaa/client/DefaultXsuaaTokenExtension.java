package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaTokenExtension;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Experimental
 *
 * <p>Service responsible for exchanging an IAS (Identity Authentication Service) ID token for an
 * XSUAA (XS Advanced User Account and Authentication) token using the OAuth 2.0 JWT Bearer Token
 * flow.
 *
 * <p>This service supports both client credentials and certificate-based authentication depending
 * on the configuration of the target XSUAA service instance. The IAS token must contain the {@code
 * app_tid} claim, which is required for tenant resolution during token exchange.
 */
public class DefaultXsuaaTokenExtension implements XsuaaTokenExtension {

  private static final Logger LOGGER = LoggerFactory.getLogger(DefaultXsuaaTokenExtension.class);

  private final OAuth2TokenService tokenService;
  private final OAuth2ServiceConfiguration xsuaaConfig;
  private static final String CLAIM_APP_TID = "app_tid";
  private static final String CERTIFICATE = "certificate";
  private static final String KEY = "key";

  public DefaultXsuaaTokenExtension(
      OAuth2TokenService tokenService, OAuth2ServiceConfiguration xsuaaConfig) {
    this.tokenService = Objects.requireNonNull(tokenService);
    this.xsuaaConfig = Objects.requireNonNull(xsuaaConfig);
  }

  /**
   * Resolves the XSUAA token from the extended security context.
   *
   * @return the XSUAA token or null if not available.
   */
  @Override
  public Token resolveXsuaaToken() {
    final Token idToken = SecurityContext.getIdToken();
    if (idToken == null) {
      LOGGER.warn("Cannot resolve XSUAA token with no ID token present");
      return null;
    }
    try {
      return exchangeToXsuaa(idToken);
    } catch (OAuth2ServiceException e) {
      LOGGER.warn("Failed to retrieve XSUAA-Token", e);
      return null;
    }
  }

  /**
   * Exchanges an IAS ID token for an XSUAA token using the JWT Bearer Token flow.
   *
   * @param idToken the strong IAS token
   * @return the exchanged XSUAA token
   * @throws OAuth2ServiceException in case of errors
   */
  private Token exchangeToXsuaa(final Token idToken) throws OAuth2ServiceException {
    final ClientIdentity identity;
    final String zid =
        Optional.ofNullable(idToken.getClaimAsString(CLAIM_APP_TID))
            .orElseThrow(() -> new IllegalStateException("IAS token missing 'app_tid'"));
    final String certPem = xsuaaConfig.getProperty(CERTIFICATE);
    final String keyPem = xsuaaConfig.getProperty(KEY);
    final String clientId = xsuaaConfig.getClientId();
    final Map<String, String> params = Map.of("token_format", "jwt");
    final XsuaaDefaultEndpoints endpoints = new XsuaaDefaultEndpoints(xsuaaConfig);
    final URI tokenEndpoint = endpoints.getTokenEndpoint();

    if (endpoints.isCertificateCredentialType()) {
      identity = new ClientCertificate(certPem, keyPem, clientId);
    } else {
      identity = new ClientCredentials(clientId, xsuaaConfig.getClientSecret());
    }
    return Token.create(
        tokenService
            .retrieveAccessTokenViaJwtBearerTokenGrant(
                tokenEndpoint, identity, idToken.getTokenValue(), params, false, zid)
            .getAccessToken());
  }
}
