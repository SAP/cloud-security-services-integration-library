package com.sap.cloud.security.servlet;

import static com.sap.cloud.security.servlet.HybridTokenFactory.isXsuaaToken;
import static com.sap.cloud.security.servlet.HybridTokenFactory.removeBearer;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.DefaultIdTokenExtension;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.http.impl.client.CloseableHttpClient;

/**
 * Authenticates HTTP requests carrying either an IAS Access Token, ID token or an XSUAA access
 * token in the {@code Authorization} header.
 *
 * <p>If the token is already an XSUAA token, validation is delegated to {@link
 * XsuaaTokenAuthenticator}. Otherwise, the IAS token is validated via {@link
 * IasTokenAuthenticator}, and on success, exchanged for an XSUAA access token using the OAuth 2.0
 * JWT Bearer Token grant ({@code jwt_bearer}). The exchanged XSUAA token is then stored in the
 * {@link com.sap.cloud.security.token.SecurityContext} and used for subsequent authorization.
 *
 * <p>Requirements:
 *
 * <ul>
 *   <li>XSUAA instance must support the {@code jwt_bearer} grant type.
 *   <li>The IAS ID token must contain the {@code app_tid} (tenant) claim.
 *   <li>Either client secret or certificate credentials must be configured for XSUAA.
 * </ul>
 *
 * <p>This authenticator is stateless and thread-safe. It should be invoked once per request,
 * typically from a servlet filter. Ensure the {@link com.sap.cloud.security.token.SecurityContext}
 * is cleared after each request to prevent token leakage between threads.
 */
public class HybridTokenAuthenticator extends AbstractTokenAuthenticator {

  private static final String CLAIM_APP_TID = "app_tid";
  private static final String CERTIFICATE = "certificate";
  private static final String KEY = "key";

  private final OAuth2ServiceConfiguration xsuaaConfig;
  private final OAuth2TokenService tokenService;
  private final IasTokenAuthenticator iasTokenAuthenticator = new IasTokenAuthenticator();
  private final XsuaaTokenAuthenticator xsuaaTokenAuthenticator = new XsuaaTokenAuthenticator();

  public HybridTokenAuthenticator(
      @Nonnull final OAuth2ServiceConfiguration iasConfig,
      @Nonnull final CloseableHttpClient httpClient,
      @Nonnull final OAuth2ServiceConfiguration xsuaaConfig) {
    this.tokenService = new DefaultOAuth2TokenService(httpClient);
    this.xsuaaConfig = xsuaaConfig;
    SecurityContext.registerIdTokenExtension(new DefaultIdTokenExtension(tokenService, iasConfig));
  }

  @Override
  public TokenAuthenticationResult validateRequest(
      final ServletRequest request, final ServletResponse response) {

    if (!(request instanceof HttpServletRequest httpRequest
        && response instanceof HttpServletResponse)) {
      return unauthenticated("Could not process request " + request);
    }
    final String authz = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
    if (!headerIsAvailable(authz)) {
      return unauthenticated("Authorization header is missing.");
    }
    DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(removeBearer(authz));

    // If token is already an XSUAA token, delegate to XSUAA authenticator
    if (isXsuaaToken(decodedJwt)) {
      return xsuaaTokenAuthenticator.validateRequest(httpRequest, response);
    }

    // Otherwise, treat it as an IAS token
    final TokenAuthenticationResult iasResult =
        iasTokenAuthenticator.validateRequest(httpRequest, response);
    if (!iasResult.isAuthenticated()) {
      return iasResult;
    }
    try {
      final Token idToken = SecurityContext.getIdToken();
      if (idToken == null) {
        return unauthenticated("Missing IAS ID Token. Cannot exchange for XSUAA Token.");
      }
      final Token xsuaaToken = exchangeToXsuaa(idToken);
      SecurityContext.overwriteToken(xsuaaToken);
      return xsuaaTokenAuthenticator.authenticated(xsuaaToken);
    } catch (OAuth2ServiceException | IllegalArgumentException | IllegalStateException e) {
      return unauthenticated(
          "Unexpected error during exchange from ID token to XSUAA token:" + e.getMessage());
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
      identity = new ClientCertificate(clientId, certPem, keyPem);
    } else {
      identity = new ClientCredentials(clientId, xsuaaConfig.getClientSecret());
    }
    return Token.create(
        "Bearer "
            + tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
                tokenEndpoint, identity, idToken.getTokenValue(), params, false, zid));
  }

  @Override
  protected OAuth2ServiceConfiguration getServiceConfiguration() {
    return xsuaaTokenAuthenticator.getServiceConfiguration();
  }

  @Nullable
  @Override
  protected OAuth2ServiceConfiguration getOtherServiceConfiguration() {
    return xsuaaTokenAuthenticator.getOtherServiceConfiguration();
  }

  @Override
  protected Token extractFromHeader(final String authorizationHeader) {
    return xsuaaTokenAuthenticator.extractFromHeader(authorizationHeader);
  }
}
