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

/** Security regression reproducer for explicit HybridTokenAuthenticator configuration handling. */
class HybridTokenAuthenticatorConfigurationSecurityTest {

  @Test
  void acceptsTokenForAmbientIasBindingInsteadOfExplicitlyConfiguredIasBinding()
      throws IOException {
    OAuth2ServiceConfiguration ambientIasConfig =
        OAuth2ServiceConfigurationBuilder.forService(Service.IAS)
            .withDomains("myauth.com")
            .withClientId("T000310")
            .build();

    OAuth2ServiceConfiguration explicitlyTrustedIasConfig =
        OAuth2ServiceConfigurationBuilder.forService(Service.IAS)
            .withDomains("trusted.example")
            .withClientId("trusted-client")
            .build();

    OAuth2ServiceConfiguration explicitlyConfiguredXsuaa =
        OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
            .withDomains("trusted-xsuaa.example")
            .withClientId("trusted-xsuaa-client")
            .withProperty(ServiceConstants.XSUAA.APP_ID, "trusted-app")
            .build();

    SecurityHttpClient defaultHttpClient = mock(SecurityHttpClient.class);
    SecurityHttpResponse discoveryResponse =
        HttpClientTestFactory.createHttpResponse(
            "{\"jwks_uri\":\"https://application.myauth.com/oauth2/certs\"}");
    SecurityHttpResponse jwksResponse =
        HttpClientTestFactory.createHttpResponse(
            IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));
    when(defaultHttpClient.execute(any(SecurityHttpRequest.class)))
        .thenReturn(discoveryResponse, jwksResponse);

    Environment ambientEnvironment = mock(Environment.class);
    when(ambientEnvironment.getIasConfiguration()).thenReturn(ambientIasConfig);
    when(ambientEnvironment.getXsuaaConfiguration()).thenReturn(null);
    when(ambientEnvironment.getXsuaaConfigurationForTokenExchange()).thenReturn(null);

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    String ambientToken = IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8).trim();
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + ambientToken);

    try (MockedStatic<Environments> environments = mockStatic(Environments.class);
        MockedStatic<SecurityHttpClientProvider> clients =
            mockStatic(SecurityHttpClientProvider.class)) {
      environments.when(Environments::getCurrent).thenReturn(ambientEnvironment);
      clients
          .when(() -> SecurityHttpClientProvider.createClient(any()))
          .thenReturn(defaultHttpClient);

      HybridTokenAuthenticator authenticator =
          new HybridTokenAuthenticator(
              explicitlyTrustedIasConfig,
              mock(SecurityHttpClient.class),
              explicitlyConfiguredXsuaa,
              DISABLED);

      TokenAuthenticationResult result = authenticator.validateRequest(request, response);

      assertThat(result.isAuthenticated())
          .as(
              "a token for the ambient myauth.com/T000310 binding must not be accepted when the "
                  + "authenticator was explicitly configured for trusted.example/trusted-client")
          .isFalse();
    }
  }

  @Test
  void acceptsTokenForAmbientXsuaaBindingInsteadOfExplicitlyConfiguredXsuaaBinding()
      throws IOException {
    OAuth2ServiceConfiguration ambientXsuaaConfig =
        OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
            .withDomains("auth.com")
            .withClientId("clientId")
            .withClientSecret("ambient-secret")
            .withUrl("https://myauth.com")
            .withProperty(ServiceConstants.XSUAA.APP_ID, "appId")
            .build();

    OAuth2ServiceConfiguration explicitlyConfiguredIas =
        OAuth2ServiceConfigurationBuilder.forService(Service.IAS)
            .withDomains("trusted-ias.example")
            .withClientId("trusted-ias-client")
            .build();

    OAuth2ServiceConfiguration explicitlyTrustedXsuaaConfig =
        OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
            .withDomains("trusted-xsuaa.example")
            .withClientId("trusted-xsuaa-client")
            .withClientSecret("trusted-secret")
            .withUrl("https://trusted-xsuaa.example")
            .withProperty(ServiceConstants.XSUAA.APP_ID, "trusted-app")
            .build();

    SecurityHttpClient defaultHttpClient = mock(SecurityHttpClient.class);
    SecurityHttpResponse jwksResponse =
        HttpClientTestFactory.createHttpResponse(
            IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));
    when(defaultHttpClient.execute(any(SecurityHttpRequest.class))).thenReturn(jwksResponse);

    Environment ambientEnvironment = mock(Environment.class);
    when(ambientEnvironment.getIasConfiguration()).thenReturn(null);
    when(ambientEnvironment.getXsuaaConfiguration()).thenReturn(ambientXsuaaConfig);
    when(ambientEnvironment.getXsuaaConfigurationForTokenExchange()).thenReturn(null);

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    String ambientToken =
        IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8).trim();
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + ambientToken);

    try (MockedStatic<Environments> environments = mockStatic(Environments.class);
        MockedStatic<SecurityHttpClientProvider> clients =
            mockStatic(SecurityHttpClientProvider.class)) {
      environments.when(Environments::getCurrent).thenReturn(ambientEnvironment);
      clients
          .when(() -> SecurityHttpClientProvider.createClient(any()))
          .thenReturn(defaultHttpClient);

      HybridTokenAuthenticator authenticator =
          new HybridTokenAuthenticator(
              explicitlyConfiguredIas,
              mock(SecurityHttpClient.class),
              explicitlyTrustedXsuaaConfig,
              DISABLED);

      TokenAuthenticationResult result = authenticator.validateRequest(request, response);

      assertThat(result.isAuthenticated())
          .as(
              "a token for the ambient auth.com/clientId binding must not be accepted when the "
                  + "authenticator was explicitly configured for trusted-xsuaa.example/"
                  + "trusted-xsuaa-client")
          .isFalse();
    }
  }


}
