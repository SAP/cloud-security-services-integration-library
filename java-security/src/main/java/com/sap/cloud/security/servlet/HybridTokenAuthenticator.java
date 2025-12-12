package com.sap.cloud.security.servlet;

import static com.sap.cloud.security.servlet.HybridTokenFactory.isXsuaaToken;
import static com.sap.cloud.security.servlet.HybridTokenFactory.removeBearer;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.DefaultIdTokenExtension;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenExchangeMode;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A token authenticator that validates and processes JSON Web Tokens (JWTs) issued by either the
 * SAP Identity Authentication Service (IAS) or the SAP Authorization and Trust Management Service
 * (XSUAA).
 *
 * <p>This authenticator validates bearer tokens and creates authenticated token objects. It
 * automatically determines the token's issuer and applies the appropriate validation rules,
 * supporting hybrid authentication scenarios where both IAS and XSUAA tokens are accepted.
 *
 * <h3>Authentication Flow</h3>
 *
 * The authenticator performs the following steps:
 *
 * <ol>
 *   <li>Accepts an encoded JWT string
 *   <li>Determines whether the token was issued by IAS or XSUAA
 *   <li>Validates the token using the appropriate validator
 *   <li>Optionally exchanges IAS tokens for XSUAA tokens based on the configured {@link
 *       TokenExchangeMode}
 *   <li>Returns a validated {@link Token} object
 * </ol>
 *
 * <h3>Token Exchange Modes</h3>
 *
 * The authenticator supports three token exchange modes:
 *
 * <ul>
 *   <li>{@link TokenExchangeMode#DISABLED}: No token exchange is performed. The original token is
 *       returned after validation.
 *   <li>{@link TokenExchangeMode#PROVIDE_XSUAA}: IAS tokens are validated and exchanged for XSUAA
 *       tokens. The XSUAA token is stored in {@link SecurityContext}, but the original IAS token is
 *       returned.
 *   <li>{@link TokenExchangeMode#FORCE_XSUAA}: IAS tokens are exchanged for XSUAA tokens, and the
 *       exchanged token is returned. XSUAA tokens are returned directly without exchange.
 * </ul>
 *
 * <h3>Client Certificate Support</h3>
 *
 * For mutual TLS (mTLS) scenarios, client certificates can be provided to the authenticator. The
 * certificate is automatically extracted and made available via {@link
 * SecurityContext#getClientCertificate()}.
 *
 * <h3>Thread Safety</h3>
 *
 * This class is thread-safe and can be reused across multiple authentication attempts.
 *
 * @see Token
 * @see TokenExchangeMode
 * @see SecurityContext
 * @see com.sap.cloud.security.token.validation.CombiningValidator
 */
public class HybridTokenAuthenticator extends AbstractTokenAuthenticator {

  private final IasTokenAuthenticator iasTokenAuthenticator = new IasTokenAuthenticator();
  private final XsuaaTokenAuthenticator xsuaaTokenAuthenticator = new XsuaaTokenAuthenticator();
  private final TokenExchangeMode tokenExchangeMode;
  private final Logger logger = LoggerFactory.getLogger(getClass());

  public HybridTokenAuthenticator(
      @Nonnull final OAuth2ServiceConfiguration iasConfig,
      @Nonnull final CloseableHttpClient httpClient,
      @Nonnull final OAuth2ServiceConfiguration xsuaaConfig,
      @Nonnull final TokenExchangeMode tokenExchangeMode) {
    this.tokenExchangeMode = tokenExchangeMode;
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
      switch (tokenExchangeMode) {
        case PROVIDE_XSUAA -> {
          logger.debug("Token exchange mode is 'PROVIDE_XSUAA'. Exchanging token...");
          SecurityContext.getXsuaaToken();
        }
        case FORCE_XSUAA -> {
          logger.debug(
              "Token exchange mode is 'FORCE_XSUAA' and token is issued by IAS. Exchanging token...");
          final Token xsuaaToken = SecurityContext.getXsuaaToken();
          SecurityContext.updateToken(xsuaaToken);
          return xsuaaTokenAuthenticator.authenticated(xsuaaToken);
        }
        case DISABLED -> logger.debug("Token exchange is disabled. No exchange performed.");
      }
    } catch (IllegalArgumentException | IllegalStateException e) {
      return unauthenticated(
          "Unexpected error during exchange from ID token to XSUAA token:" + e.getMessage());
    }
    return iasResult;
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
