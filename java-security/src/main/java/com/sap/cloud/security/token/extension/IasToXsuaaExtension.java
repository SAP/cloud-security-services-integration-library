package com.sap.cloud.security.token.extension;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.context.ContextExtension;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import java.net.URI;
import java.util.*;
import org.apache.http.impl.client.CloseableHttpClient;

/**
 * Exchanges IAS weak -> IAS strong, and optionally IAS strong -> XSUAA. Stores results as context
 * attachments and (optionally) switches primary token.
 */
public class IasToXsuaaExtension implements ContextExtension {

  public enum Mode {
    NONE,
    TO_IAS, // weak IAS -> strong IAS
    TO_XSUAA // weak IAS -> strong IAS -> XSUAA
  }

  private final OAuth2ServiceConfiguration iasConfig;
  private final OAuth2ServiceConfiguration xsuaaConfig;
  private final Mode mode;
  private final OAuth2TokenService tokenService;

  /**
   * Creates a new IAS to XSUAA extension.
   *
   * @param iasConfig the IAS service configuration (client id/secret or certificate)
   * @param mode the mode of operation, NONE, TO_IAS or TO_XSUAA
   * @param httpClient the HTTP client to use
   * @param xsuaaConfig the XSUAA service configuration (client id/secret or certificate), required
   *     if mode is TO_XSUAA
   */
  public IasToXsuaaExtension(
      final OAuth2ServiceConfiguration iasConfig,
      final Mode mode,
      final CloseableHttpClient httpClient,
      final OAuth2ServiceConfiguration xsuaaConfig) {
    this.iasConfig = Objects.requireNonNull(iasConfig, "iasConfig must not be null");
    this.mode = Objects.requireNonNull(mode, "mode must not be null");
    this.tokenService = new DefaultOAuth2TokenService(httpClient);
    this.xsuaaConfig = xsuaaConfig;
  }

  /** Creates a new IAS to XSUAA extension. */
  @Override
  public void extend() throws Exception {
    final Token incoming = SecurityContext.getToken();
    if (mode == Mode.NONE) {
      return;
    }

    final boolean isWeak = isWeakToken(incoming);
    Token strongIas = incoming;

    if (isWeak) {
      strongIas = exchangeToStrongIas(incoming);
      SecurityContext.attach(SecurityContext.ATTACH_ORIGINAL, incoming);
      SecurityContext.attach(SecurityContext.ATTACH_IAS_STRONG, strongIas);
    }

    if (mode == Mode.TO_IAS) {
      SecurityContext.setToken(strongIas);
      return;
    }

    if (mode == Mode.TO_XSUAA) {
      final Token xsuaa = exchangeToXsuaa(strongIas);
      SecurityContext.attach(SecurityContext.ATTACH_XSUAA, xsuaa);
      SecurityContext.setToken(xsuaa);
    }
  }

  /**
   * Exchanges a weak IAS token for a strong IAS token using the JWT Bearer Token flow.
   *
   * @param weakIas the weak IAS token
   * @return the exchanged strong IAS token
   * @throws Exception in case of errors
   */
  private Token exchangeToStrongIas(final Token weakIas) throws Exception {
    final String issuer = weakIas.getIssuer();
    final String certPem = iasConfig.getProperty("certificate");
    final String keyPem = iasConfig.getProperty("key");
    final ClientIdentity clientIdentity =
        (certPem != null && keyPem != null)
            ? new ClientCertificate(iasConfig.getClientId(), certPem, keyPem)
            : new ClientCredentials(iasConfig.getClientId(), iasConfig.getClientSecret());

    final URI tokenEndpoint = deriveIasTokenEndpoint(issuer);
    final Map<String, String> params = new HashMap<>();
    params.put("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
    params.put("assertion", weakIas.getTokenValue());
    params.put("token_format", "jwt");
    params.put("refresh_expiry", "0");
    params.put("client_id", iasConfig.getClientId());

    final OAuth2TokenResponse response =
        tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            tokenEndpoint, clientIdentity, weakIas.getTokenValue(), null, params, false);

    final String jwt = response.getAccessToken();
    return new SapIdToken("Bearer " + jwt);
  }

  /**
   * Exchanges a strong IAS token for an XSUAA token using the JWT Bearer Token flow.
   *
   * @param iasStrong the strong IAS token
   * @return the exchanged XSUAA token
   * @throws Exception in case of errors
   */
  private Token exchangeToXsuaa(final Token iasStrong) throws Exception {
    final String zid =
        Optional.ofNullable(iasStrong.getClaimAsString("app_tid"))
            .orElseThrow(() -> new IllegalStateException("IAS token missing 'app_tid'"));
    final OAuth2ServiceEndpointsProvider endpoints = new XsuaaDefaultEndpoints(xsuaaConfig);
    final URI tokenEndpoint = endpoints.getTokenEndpoint();
    final ClientIdentity clientIdentity;
    final String cert = xsuaaConfig.getProperty("certificate");
    final String key = xsuaaConfig.getProperty("key");
    if (cert != null && key != null) {
      clientIdentity = new ClientCertificate(xsuaaConfig.getClientId(), cert, key);
    } else {
      clientIdentity =
          new ClientCredentials(xsuaaConfig.getClientId(), xsuaaConfig.getClientSecret());
    }
    final Map<String, String> optionalParams = new HashMap<>();
    optionalParams.put("token_format", "jwt");
    final OAuth2TokenResponse response =
        tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            tokenEndpoint, clientIdentity, iasStrong.getTokenValue(), optionalParams, false, zid);

    final String jwtXsuaa = response.getAccessToken();
    return Token.create("Bearer " + jwtXsuaa);
  }

  /**
   * Derives the IAS token endpoint from the issuer URL. Examples:
   *
   * <ul>
   *   <li>https://&lt;domain&gt;/oauth2/token -&gt; https://&lt;domain&gt;/oauth2/token
   *   <li>https://&lt;domain&gt;/oauth2 -&gt; https://&lt;domain&gt;/oauth2/token
   *   <li>https://&lt;domain&gt; -&gt; https://&lt;domain&gt;/oauth2/token
   * </ul>
   *
   * @param issuer the issuer URL from the IAS token
   * @return the IAS token endpoint URL
   */
  private static URI deriveIasTokenEndpoint(final String issuer) {
    String base = issuer;
    if (base.endsWith("/")) {
      base = base.substring(0, base.length() - 1);
    }
    if (base.endsWith("/oauth2/token")) {
      return URI.create(base);
    }
    if (base.endsWith("/oauth2")) {
      return URI.create(base + "/token");
    }
    return URI.create(base + "/oauth2/token");
  }

  /**
   * Determines if the provided token is a weak IAS token by checking for the presence of the
   * "ias_apis" claim.
   *
   * @param token token to be checked
   * @return true if provided token is a weak IAS token
   */
  private static boolean isWeakToken(final Token token) {
    try {
      final List<String> apis = token.getClaimAsStringList("ias_apis");
      return apis != null && !apis.isEmpty();
    } catch (final Exception ignore) {
      return false;
    }
  }
}
