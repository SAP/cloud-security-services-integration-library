package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.config.Service.XSUAA;

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
 * Default implementation of {@link XsuaaTokenExtension} that exchanges IAS tokens to XSUAA tokens.
 *
 * <p>This implementation enables <b>hybrid authentication scenarios (Level 0 migration)</b> where
 * an application receives Identity Authentication Service (IAS) tokens but needs XSUAA tokens to
 * maintain compatibility with existing XSUAA-based authorization logic (scopes, attributes, role
 * collections).
 *
 * <p><b>Token Exchange Flow:</b>
 *
 * <ol>
 *   <li>Retrieves the current token from {@link SecurityContext#getToken()}
 *   <li>If already a XSUAA token, returns it immediately (no exchange needed)
 *   <li>If IAS token, exchanges it to XSUAA format
 * </ol>
 *
 * <p><b>Prerequisites:</b> Token exchange requires both service bindings in your Cloud Foundry
 * manifest:
 *
 * <pre>{@code
 * services:
 *   - name: xsuaa-authn
 *   - name: ias-authn
 *     parameters:
 *       xsuaa-cross-consumption: true  # Required for token exchange
 * }</pre>
 *
 * The {@code xsuaa-cross-consumption: true} parameter allows IAS to fetch XSUAA service keys for
 * JWT Bearer token exchange.
 *
 * @see XsuaaTokenExtension
 * @see SecurityContext#registerXsuaaTokenExtension(XsuaaTokenExtension)
 */
public class DefaultXsuaaTokenExtension implements XsuaaTokenExtension {

  private static final Logger LOGGER = LoggerFactory.getLogger(DefaultXsuaaTokenExtension.class);

  private final OAuth2TokenService tokenService;
  private final OAuth2ServiceConfiguration xsuaaConfig;
  private static final String CLAIM_APP_TID = "app_tid";
  private static final String CERTIFICATE = "certificate";
  private static final String KEY = "key";

  /**
   * Creates a new {@link DefaultXsuaaTokenExtension} with the specified token service and XSUAA
   * configuration.
   *
   * @param tokenService the OAuth2 token service to use for token exchange (must not be {@code
   *     null})
   * @param xsuaaConfig the XSUAA OAuth2 service configuration containing client credentials and
   *     token endpoints (must not be {@code null})
   * @throws NullPointerException if {@code tokenService} or {@code xsuaaConfig} is {@code null}
   */
  public DefaultXsuaaTokenExtension(
      OAuth2TokenService tokenService, OAuth2ServiceConfiguration xsuaaConfig) {
    this.tokenService = Objects.requireNonNull(tokenService);
    this.xsuaaConfig = Objects.requireNonNull(xsuaaConfig);
  }

  /**
   * Resolves a XSUAA token by exchanging the current IAS token from {@link SecurityContext}.
   *
   * <p><b>Execution Flow:</b>
   *
   * <ol>
   *   <li>Retrieves the current token using {@link SecurityContext#getToken()}
   *   <li>Returns {@code null} if no token is available
   *   <li>Returns the current token immediately if it's already a XSUAA token (no exchange needed)
   *   <li>Exchanges IAS tokens to XSUAA tokens using {@link
   *       OAuth2TokenService#retrieveAccessTokenViaJwtBearerTokenGrant}
   *   <li>Returns the exchanged XSUAA token
   * </ol>
   *
   * <p><b>Failure Scenarios:</b> Returns {@code null} if:
   *
   * <ul>
   *   <li>No token exists in {@link SecurityContext} (DEBUG: "Cannot resolve XSUAA token: No token
   *       found")
   *   <li>Token exchange fails due to:
   *       <ul>
   *         <li>Network errors
   *         <li>Missing {@code xsuaa-cross-consumption: true} configuration
   *         <li>Invalid XSUAA credentials
   *         <li>XSUAA service unavailable
   *       </ul>
   * </ul>
   *
   * @return the XSUAA token (either existing or exchanged), or {@code null} if resolution fails
   */
  @Override
  public Token resolveXsuaaToken() {
    final Token currentToken = SecurityContext.getToken();
    if (currentToken != null && currentToken.getService() == XSUAA) {
      return currentToken;
    }
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
