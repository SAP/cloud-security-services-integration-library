/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import static com.sap.cloud.security.token.TokenExchangeMode.DISABLED;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpClientProvider;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;
import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.util.HttpClientTestFactory;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

/**
 * Verifies that HybridTokenAuthenticator uses the IAS and XSUAA configurations supplied to its
 * constructor for token validation, not the ambient service bindings from Environments.getCurrent().
 */
class HybridTokenAuthenticatorConfigurationTest {

  // IAS fixture token: iss=https://application.myauth.com, azp/aud=T000310
  private static final String AMBIENT_IAS_DOMAIN = "myauth.com";
  private static final String AMBIENT_IAS_CLIENT_ID = "T000310";

  // XSUAA fixture token: iss=http://auth.com, aud/cid=clientId
  private static final String AMBIENT_XSUAA_DOMAIN = "auth.com";
  private static final String AMBIENT_XSUAA_CLIENT_ID = "clientId";

  @Test
  void iasToken_forAmbientBinding_isRejectedWhenConstructedWithDifferentConfig() throws IOException {
    OAuth2ServiceConfiguration ambientIasConfig = iasConfig(AMBIENT_IAS_DOMAIN, AMBIENT_IAS_CLIENT_ID);
    OAuth2ServiceConfiguration trustedIasConfig = iasConfig("trusted.example", "trusted-client");
    OAuth2ServiceConfiguration trustedXsuaaConfig = xsuaaConfig("trusted-xsuaa.example", "trusted-xsuaa-client");

    SecurityHttpClient httpClient = mock(SecurityHttpClient.class);
    when(httpClient.execute(any(SecurityHttpRequest.class)))
        .thenReturn(discoveryResponse())
        .thenReturn(iasJwksResponse());

    Environment ambientEnv = ambientEnvironment(ambientIasConfig, null);

    HttpServletRequest request = requestWithToken(iasToken());

    try (MockedStatic<Environments> envs = mockStatic(Environments.class);
        MockedStatic<SecurityHttpClientProvider> clients = mockStatic(SecurityHttpClientProvider.class)) {
      envs.when(Environments::getCurrent).thenReturn(ambientEnv);
      clients.when(() -> SecurityHttpClientProvider.createClient(any())).thenReturn(httpClient);

      HybridTokenAuthenticator authenticator =
          new HybridTokenAuthenticator(trustedIasConfig, mock(SecurityHttpClient.class), trustedXsuaaConfig, DISABLED);

      TokenAuthenticationResult result = authenticator.validateRequest(request, mock(HttpServletResponse.class));

      assertThat(result.isAuthenticated())
          .as("IAS token for ambient binding %s/%s must be rejected when authenticator is configured for trusted.example/trusted-client",
              AMBIENT_IAS_DOMAIN, AMBIENT_IAS_CLIENT_ID)
          .isFalse();
    }
  }

  @Test
  void xsuaaToken_forAmbientBinding_isRejectedWhenConstructedWithDifferentConfig() throws IOException {
    OAuth2ServiceConfiguration ambientXsuaaConfig = xsuaaConfig(AMBIENT_XSUAA_DOMAIN, AMBIENT_XSUAA_CLIENT_ID);
    OAuth2ServiceConfiguration trustedIasConfig = iasConfig("trusted-ias.example", "trusted-ias-client");
    OAuth2ServiceConfiguration trustedXsuaaConfig = xsuaaConfig("trusted-xsuaa.example", "trusted-xsuaa-client");

    SecurityHttpClient httpClient = mock(SecurityHttpClient.class);
    when(httpClient.execute(any(SecurityHttpRequest.class))).thenReturn(xsuaaJwksResponse());

    Environment ambientEnv = ambientEnvironment(null, ambientXsuaaConfig);

    HttpServletRequest request = requestWithToken(xsuaaToken());

    try (MockedStatic<Environments> envs = mockStatic(Environments.class);
        MockedStatic<SecurityHttpClientProvider> clients = mockStatic(SecurityHttpClientProvider.class)) {
      envs.when(Environments::getCurrent).thenReturn(ambientEnv);
      clients.when(() -> SecurityHttpClientProvider.createClient(any())).thenReturn(httpClient);

      HybridTokenAuthenticator authenticator =
          new HybridTokenAuthenticator(trustedIasConfig, mock(SecurityHttpClient.class), trustedXsuaaConfig, DISABLED);

      TokenAuthenticationResult result = authenticator.validateRequest(request, mock(HttpServletResponse.class));

      assertThat(result.isAuthenticated())
          .as("XSUAA token for ambient binding %s/%s must be rejected when authenticator is configured for trusted-xsuaa.example/trusted-xsuaa-client",
              AMBIENT_XSUAA_DOMAIN, AMBIENT_XSUAA_CLIENT_ID)
          .isFalse();
    }
  }

  @Test
  void iasToken_forExplicitlyConfiguredBinding_isAcceptedEvenWhenNoAmbientConfigExists() throws IOException {
    // myauth.com is both the explicit config and matches the fixture token — validates correctly
    OAuth2ServiceConfiguration explicitIasConfig = iasConfig(AMBIENT_IAS_DOMAIN, AMBIENT_IAS_CLIENT_ID);
    OAuth2ServiceConfiguration explicitXsuaaConfig = xsuaaConfig("some-xsuaa.example", "some-client");

    SecurityHttpClient httpClient = mock(SecurityHttpClient.class);
    when(httpClient.execute(any(SecurityHttpRequest.class)))
        .thenReturn(discoveryResponse())
        .thenReturn(iasJwksResponse());

    // No ambient IAS config — ensures the authenticator relies only on what was passed in
    Environment emptyEnv = ambientEnvironment(null, null);

    HttpServletRequest request = requestWithToken(iasToken());

    try (MockedStatic<Environments> envs = mockStatic(Environments.class);
        MockedStatic<SecurityHttpClientProvider> clients = mockStatic(SecurityHttpClientProvider.class)) {
      envs.when(Environments::getCurrent).thenReturn(emptyEnv);
      clients.when(() -> SecurityHttpClientProvider.createClient(any())).thenReturn(httpClient);

      HybridTokenAuthenticator authenticator =
          new HybridTokenAuthenticator(explicitIasConfig, httpClient, explicitXsuaaConfig, DISABLED);

      TokenAuthenticationResult result = authenticator.validateRequest(request, mock(HttpServletResponse.class));

      assertThat(result.isAuthenticated())
          .as("IAS token must be accepted when the explicitly supplied config matches it, even if no ambient config exists")
          .isTrue();
    }
  }

  // --- helpers ---

  private static OAuth2ServiceConfiguration iasConfig(String domain, String clientId) {
    return OAuth2ServiceConfigurationBuilder.forService(Service.IAS)
        .withDomains(domain)
        .withClientId(clientId)
        .build();
  }

  private static OAuth2ServiceConfiguration xsuaaConfig(String domain, String clientId) {
    return OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
        .withDomains(domain)
        .withClientId(clientId)
        .withProperty(ServiceConstants.XSUAA.APP_ID, "app-" + clientId)
        .build();
  }

  private static Environment ambientEnvironment(OAuth2ServiceConfiguration ias, OAuth2ServiceConfiguration xsuaa) {
    Environment env = mock(Environment.class);
    when(env.getIasConfiguration()).thenReturn(ias);
    when(env.getXsuaaConfiguration()).thenReturn(xsuaa);
    when(env.getXsuaaConfigurationForTokenExchange()).thenReturn(null);
    return env;
  }

  private static HttpServletRequest requestWithToken(String token) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token);
    return request;
  }

  private static String iasToken() throws IOException {
    return IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8).trim();
  }

  private static String xsuaaToken() throws IOException {
    return IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8).trim();
  }

  private static SecurityHttpResponse discoveryResponse() {
    return HttpClientTestFactory.createHttpResponse(
        "{\"jwks_uri\":\"https://application.myauth.com/oauth2/certs\"}");
  }

  private static SecurityHttpResponse iasJwksResponse() throws IOException {
    return HttpClientTestFactory.createHttpResponse(
        IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));
  }

  private static SecurityHttpResponse xsuaaJwksResponse() throws IOException {
    return HttpClientTestFactory.createHttpResponse(
        IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));
  }
}
