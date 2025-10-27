package com.sap.cloud.security.servlet;


import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.DefaultIdTokenExtension;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.http.impl.client.CloseableHttpClient;

public class HybridTokenAuthenticator extends AbstractTokenAuthenticator {

  private final OAuth2ServiceConfiguration iasConfig;
  private final OAuth2ServiceConfiguration xsuaaConfig;
  private final OAuth2TokenService tokenService;

  IasTokenAuthenticator iasTokenAuthenticator = new IasTokenAuthenticator();
  XsuaaTokenAuthenticator xsuaaTokenAuthenticator = new XsuaaTokenAuthenticator();

  public HybridTokenAuthenticator(
      @Nonnull final OAuth2ServiceConfiguration iasConfig,
      @Nonnull final CloseableHttpClient httpClient,
      @Nonnull final OAuth2ServiceConfiguration xsuaaConfig) {
    this.iasConfig = iasConfig;
    this.tokenService = new DefaultOAuth2TokenService(httpClient);
    this.xsuaaConfig = xsuaaConfig;
  }

  @Override
  public TokenAuthenticationResult validateRequest(
      final ServletRequest request, final ServletResponse response) {
    final TokenAuthenticationResult authenticationResult =
        iasTokenAuthenticator.validateRequest(request, response);
    if (authenticationResult.isAuthenticated()) {
      if (SecurityContext.getToken() instanceof XsuaaToken) {
        return authenticationResult;
      }
      try {
        SecurityContext.registerIdTokenExtension(
            new DefaultIdTokenExtension(tokenService, iasConfig));
        final Token idToken = SecurityContext.getIdToken();
        if (idToken == null) {
          return authenticationResult;
        }
        final Token xsuaaToken = exchangeToXsuaa(idToken);
        final TokenAuthenticationResult xsuaaAuthenticationResult =
            xsuaaTokenAuthenticator.authenticated(xsuaaToken);
        SecurityContext.overwriteToken(xsuaaToken);
        return xsuaaAuthenticationResult;
      } catch (final OAuth2ServiceException e) {
        return authenticationResult;
      }
    } else {
      return authenticationResult;
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
        Optional.ofNullable(idToken.getClaimAsString("app_tid"))
            .orElseThrow(() -> new IllegalStateException("IAS token missing 'app_tid'"));
    final String certPem = xsuaaConfig.getProperty("certificate");
    final String keyPem = xsuaaConfig.getProperty("key");
    final String clientId = xsuaaConfig.getClientId();
    final Map<String, String> params = new HashMap<>();
    params.put("token_format", "jwt");
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
    final OAuth2ServiceConfiguration config =
        serviceConfiguration != null
            ? serviceConfiguration
            : Environments.getCurrent().getXsuaaConfiguration();
    if (config == null) {
      throw new IllegalStateException("There must be a service configuration.");
    }
    return config;
  }

  @Nullable
  @Override
  protected OAuth2ServiceConfiguration getOtherServiceConfiguration() {
    return null;
  }

  @Override
  protected Token extractFromHeader(final String authorizationHeader) {
    return new SapIdToken(authorizationHeader);
  }
}
