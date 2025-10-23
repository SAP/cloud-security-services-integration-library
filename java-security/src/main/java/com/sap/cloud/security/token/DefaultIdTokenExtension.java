package com.sap.cloud.security.token;

import static java.util.Objects.nonNull;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@code DefaultIdTokenExtension} provides support for resolving an ID token for the current user
 * based on the token available in the {@link SecurityContext}.
 *
 * <p>This implementation converts an access token into an ID token by invoking the IAS token
 * endpoint using the JWT bearer token grant flow.
 *
 * <p>Resolution behavior:
 *
 * <ul>
 *   <li>If the current token is already an ID token, it is returned as-is.
 *   <li>If the token belongs to a technical user (where {@code sub == azp}), an exception is
 *       thrown.
 *   <li>If the token is an access token, it will be exchanged for an ID token using the configured
 *       IAS service credentials.
 * </ul>
 *
 * <p>The resolved ID token can be used for authentication or downstream service calls that
 * explicitly require an ID token instead of an access token.
 */
public class DefaultIdTokenExtension implements IdTokenExtension {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultIdTokenExtension.class);
  private final OAuth2TokenService tokenService;
  private final OAuth2ServiceConfiguration iasConfig;

  /**
   * Creates a new {@code DefaultIdTokenExtension} for exchanging access tokens into ID tokens.
   *
   * @param tokenService the OAuth 2.0 token service used to perform the exchange
   * @param iasConfig the IAS service configuration containing client credentials
   * @throws NullPointerException if any of the parameters is {@code null}
   */
  public DefaultIdTokenExtension(
      OAuth2TokenService tokenService, OAuth2ServiceConfiguration iasConfig) {
    this.tokenService = Objects.requireNonNull(tokenService);
    this.iasConfig = Objects.requireNonNull(iasConfig);
  }

  /**
   * Resolves an ID token for the current user.
   *
   * <p>The current token is obtained from {@link SecurityContext#getInitialToken()} and processed
   * as follows:
   *
   * <ul>
   *   <li>If the token represents a technical user, an {@link IllegalArgumentException} is thrown.
   *   <li>If the token is already an ID token, it is returned as-is.
   *   <li>If the token is an access token, it is exchanged via the IAS token endpoint.
   * </ul>
   *
   * @return the raw JWT string of the ID token, or {@code null} if the exchange fails
   * @throws IllegalArgumentException if the token belongs to a technical user
   */
  @Override
  public Token resolveIdToken() {
    final Token token = SecurityContext.getInitialToken();

    if (token == null) {
      throw new IllegalArgumentException("Cannot resolve ID token with no access token present");
    }

    if (isTechnicalUser(token)) {
      throw new IllegalArgumentException("Cannot get ID token for technical user.");
    }

    if (!isAccessToken(token)) {
      LOG.debug("Incoming Token is already an ID Token. Returning incoming Token");
      return token;
    }

    try {
      return Token.create(exchangeAccessToIDToken(token).getAccessToken());
    } catch (OAuth2ServiceException e) {
      LOG.warn("Failed to retrieve ID-Token", e);
      return null;
    }
  }

  /**
   * Determines whether the given token is an access token rather than an ID token.
   *
   * <p>This is inferred by checking whether the {@code aud} claim contains only the client ID of
   * the token, which indicates an access token intended for the current client application.
   *
   * @param token the token to inspect
   * @return {@code true} if the token is an access token, otherwise {@code false}
   */
  private boolean isAccessToken(Token token) {
    final List<String> audiences = token.getClaimAsStringList("aud");
    return audiences.size() == 1 && audiences.get(0).equals(token.getClientId());
  }

  /**
   * Determines whether the token represents a technical user.
   *
   * <p>A token is considered to belong to a technical user if the {@code sub} (subject) claim
   * equals the {@code azp} (authorized party / client ID) claim.
   *
   * @param token the token to inspect
   * @return {@code true} if the token belongs to a technical user
   */
  private boolean isTechnicalUser(Token token) {
    String subject = token.getClaimAsString("sub");
    String azp = token.getClientId();
    if (subject == null || azp == null || subject.isBlank() || azp.isBlank()) {
      return false;
    }
    return subject.equals(azp);
  }

  /**
   * Exchanges a IAS access token for a strong IAS ID token using the JWT bearer token grant flow.
   *
   * @param accessToken the access IAS token to exchange
   * @return the {@link OAuth2TokenResponse} containing the new ID token
   * @throws OAuth2ServiceException if the exchange fails
   */
  private OAuth2TokenResponse exchangeAccessToIDToken(Token accessToken)
      throws OAuth2ServiceException {

    final String certPem = iasConfig.getProperty("certificate");
    final String keyPem = iasConfig.getProperty("key");
    final String clientId = iasConfig.getClientId();

    final Map<String, String> params = new HashMap<>();
    params.put("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
    params.put("assertion", accessToken.getTokenValue());
    params.put("token_format", "jwt");
    params.put("refresh_expiry", "0");
    params.put("client_id", clientId);

    if (certPem != null && keyPem != null && nonNull(iasConfig.getCertUrl())) {
      final URI certUrlEndpoint = URI.create(iasConfig.getCertUrl().toString() + "/oauth2/token");
      return tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
          certUrlEndpoint,
          new ClientCertificate(clientId, certPem, keyPem),
          accessToken.getTokenValue(),
          null,
          params,
          false);
    } else {
      final URI tokenUrlEndpoint = URI.create(iasConfig.getUrl().toString() + "/oauth2/token");
      return tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
          tokenUrlEndpoint,
          new ClientCredentials(clientId, iasConfig.getClientSecret()),
          accessToken.getTokenValue(),
          null,
          params,
          false);
    }
  }
}
