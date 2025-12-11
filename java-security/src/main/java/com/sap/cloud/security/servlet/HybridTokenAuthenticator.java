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
import org.springframework.security.core.Authentication;

/**
 * Authenticates tokens issued by XSUAA or Identity Authentication Service (IAS).
 *
 * <p>This authenticator validates JWT tokens and creates Spring Security {@link Authentication}
 * objects, supporting both XSUAA access tokens and IAS OIDC tokens. It integrates with {@link
 * SecurityContext} to enable automatic token exchange in hybrid scenarios.
 *
 * <p><b>Authentication Flow:</b>
 *
 * <ol>
 *   <li>Extract JWT token from HTTP request (Authorization header)
 *   <li>Validate token using appropriate validator (XSUAA or IAS)
 *   <li>Optionally exchange IAS token to XSUAA format if enabled
 *   <li>Store token in thread-local {@link SecurityContext}
 *   <li>Return {@link Authentication} object with token claims/authorities
 * </ol>
 *
 * <p><b>Hybrid Authentication Support:</b> When token exchange is enabled, IAS tokens are
 * automatically converted to XSUAA format after validation. This supports Level 0 migration where
 * applications transition from XSUAA to IAS authentication while maintaining existing authorization
 * logic.
 *
 * <p><b>Thread Safety:</b> This class is thread-safe. Each request is processed in its own thread
 * with isolated {@link SecurityContext} storage.
 *
 * @see SecurityContext
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
      SecurityContext.updateToken(xsuaaToken);
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
