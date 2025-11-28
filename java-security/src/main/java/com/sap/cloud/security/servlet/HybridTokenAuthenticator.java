package com.sap.cloud.security.servlet;

import static com.sap.cloud.security.servlet.HybridTokenFactory.isXsuaaToken;
import static com.sap.cloud.security.servlet.HybridTokenFactory.removeBearer;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.DefaultIdTokenExtension;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.DefaultXsuaaTokenExtension;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.http.impl.client.CloseableHttpClient;

/**
 * Experimental Authenticates HTTP requests carrying either an IAS Access Token, ID token or an
 * XSUAA access token in the {@code Authorization} header.
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

  private final IasTokenAuthenticator iasTokenAuthenticator = new IasTokenAuthenticator();
  private final XsuaaTokenAuthenticator xsuaaTokenAuthenticator = new XsuaaTokenAuthenticator();

  public HybridTokenAuthenticator(
      @Nonnull final OAuth2ServiceConfiguration iasConfig,
      @Nonnull final CloseableHttpClient httpClient,
      @Nonnull final OAuth2ServiceConfiguration xsuaaConfig) {
    OAuth2TokenService tokenService = new DefaultOAuth2TokenService(httpClient);
    SecurityContext.registerIdTokenExtension(new DefaultIdTokenExtension(tokenService, iasConfig));
    SecurityContext.registerXsuaaTokenExtension(
        new DefaultXsuaaTokenExtension(tokenService, xsuaaConfig));
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
    DecodedJwt decodedJwt;
    try {
      decodedJwt = Base64JwtDecoder.getInstance().decode(removeBearer(authz));
    } catch (IllegalArgumentException e) {
      return unauthenticated("Unexpected error occurred: " + e.getMessage());
    }

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
      final Token xsuaaToken = SecurityContext.getXsuaaToken();
      if (xsuaaToken == null) {
        return unauthenticated("XSUAA Token couldn't be fetched.");
      }
      SecurityContext.overwriteToken(xsuaaToken);
      return xsuaaTokenAuthenticator.authenticated(xsuaaToken);
    } catch (IllegalArgumentException | IllegalStateException e) {
      return unauthenticated(
          "Unexpected error during exchange from ID token to XSUAA token:" + e.getMessage());
    }
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
