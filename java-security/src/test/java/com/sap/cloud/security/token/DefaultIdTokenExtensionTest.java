package com.sap.cloud.security.token;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

public class DefaultIdTokenExtensionTest {

  private final String clientId = "clientId";
  private final URI tokenUri = URI.create("http://localhost:8080");
  private final URI completeTokenUri = URI.create("http://localhost:8080/oauth2/token");

  private static final Token idToken = new MockTokenBuilder().build();
  private static final Token accessToken = new MockTokenBuilder().build();
  private static final Token technicalUserToken = new MockTokenBuilder().build();
  private static final OAuth2TokenResponse tokenResponse = Mockito.mock(OAuth2TokenResponse.class);
  private DefaultIdTokenExtension cut;
  private final OAuth2TokenService tokenService = Mockito.mock(OAuth2TokenService.class);
  private final OAuth2ServiceConfiguration serviceConfiguration =
      Mockito.mock(OAuth2ServiceConfiguration.class);

  @BeforeEach
  public void setUp() throws IOException {
    SecurityContext.clearContext();
    when(serviceConfiguration.getUrl()).thenReturn(tokenUri);
    when(serviceConfiguration.getClientId()).thenReturn(clientId);

    // Mock getClientIdentity() to return appropriate ClientIdentity based on config
    ClientCertificate clientCert = new ClientCertificate("certPem", "keyPem", clientId);
    when(serviceConfiguration.getClientIdentity()).thenReturn(clientCert); // default to cert

    String audience = "audience";
    when(idToken.getClaimAsStringList("aud")).thenReturn(List.of(audience, clientId));
    when(idToken.getClientId()).thenReturn(clientId);
    when(accessToken.getClaimAsStringList("aud")).thenReturn(List.of(audience));
    when(accessToken.getClientId()).thenReturn(clientId);
    when(accessToken.getIssuer()).thenReturn(tokenUri.toString()); // Mock issuer for multi-tenant support
    when(technicalUserToken.getClaimAsString("sub")).thenReturn(clientId);
    when(technicalUserToken.getClientId()).thenReturn(clientId);
    when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeTokenUri), any(), any(), any(), anyMap(), anyBoolean()))
        .thenReturn(tokenResponse);
    when(accessToken.getTokenValue())
        .thenReturn(IOUtils.resourceToString("/iasTokenWithCnfRSA256.txt", UTF_8));
    when(tokenResponse.getAccessToken())
        .thenReturn(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));

    cut = new DefaultIdTokenExtension(tokenService, serviceConfiguration);
  }

  @Test
  public void resolveToken_noTokenInContext_throwsIllegalArgumentException() {
    assertThatThrownBy(() -> cut.resolveIdToken(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void resolveToken_tokenIsTechnicalUser_throwsIllegalArgumentException() {
    SecurityContext.setToken(technicalUserToken);

    assertThatThrownBy(() -> cut.resolveIdToken(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void resolveIdToken_cachedTokenIsStillValid_returnToken() {
    when(idToken.isExpired()).thenReturn(false);

    final Token result = cut.resolveIdToken(idToken);

    assertThat(result).isEqualTo(idToken);
  }

  @Test
  public void resolveIdToken_tokenIsExpired_exchangeNewIdToken() throws OAuth2ServiceException {
    when(idToken.isExpired()).thenReturn(true);
    SecurityContext.setToken(accessToken);

    final Token result = cut.resolveIdToken(idToken);

    assertThat(result).isNotEqualTo(idToken);
    verify(tokenService)
        .retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeTokenUri), any(), any(), any(), any(), eq(false));
  }

  @Test
  public void resolveIdToken_tokenIsAccessTokenWithCertificate_exchangeTokenForTokenWithCert()
      throws OAuth2ServiceException {
    SecurityContext.setToken(accessToken);
    ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Map<String, String>> paramCaptor = ArgumentCaptor.forClass(Map.class);

    final Token result = cut.resolveIdToken(null);

    verify(tokenService)
        .retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeTokenUri),
            any(),
            tokenCaptor.capture(),
            any(),
            paramCaptor.capture(),
            eq(false));
    assertThat(tokenCaptor.getValue()).isEqualTo(accessToken.getTokenValue());
    Map<String, String> params = paramCaptor.getValue();
    assertThat(params.get("grant_type")).isEqualTo("urn:ietf:params:oauth:grant-type:jwt-bearer");
    assertThat(params.get("assertion")).isEqualTo(accessToken.getTokenValue());
    assertThat(params.get("token_format")).isEqualTo("jwt");
    assertThat(params.get("refresh_expiry")).isEqualTo("0");
    assertThat(params.get("client_id")).isEqualTo(clientId);
    assertThat(result.getTokenValue()).isEqualTo(tokenResponse.getAccessToken());
  }

  @Test
  public void
      resolveIdToken_tokenIsAccessTokenWithClientCredentials_exchangeTokenForTokenWithClientSecret()
          throws OAuth2ServiceException {
    SecurityContext.setToken(accessToken);
    when(serviceConfiguration.getClientIdentity()).thenReturn(new ClientCredentials(clientId, "clientSecret"));
    ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Map<String, String>> paramCaptor = ArgumentCaptor.forClass(Map.class);

    final Token result = cut.resolveIdToken(null);

    verify(tokenService)
        .retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeTokenUri),
            any(),
            tokenCaptor.capture(),
            any(),
            paramCaptor.capture(),
            eq(false));

    Map<String, String> params = paramCaptor.getValue();
    assertThat(tokenCaptor.getValue()).isEqualTo(accessToken.getTokenValue());
    assertThat(params.get("grant_type")).isEqualTo("urn:ietf:params:oauth:grant-type:jwt-bearer");
    assertThat(params.get("assertion")).isEqualTo(accessToken.getTokenValue());
    assertThat(params.get("token_format")).isEqualTo("jwt");
    assertThat(params.get("refresh_expiry")).isEqualTo("0");
    assertThat(params.get("client_id")).isEqualTo(clientId);
    assertThat(result.getTokenValue()).isEqualTo(tokenResponse.getAccessToken());
  }

  @Test
  public void resolveIdToken_tokenIsAlreadyToken_doesNotCallTokenService() {
    SecurityContext.setToken(idToken);

    final Token result = cut.resolveIdToken(null);

    assertThat(result).isSameAs(idToken);
    verifyNoInteractions(tokenService);
  }

  @Test
  public void resolveToken_exchangeFails_returnsNull() throws OAuth2ServiceException {
    SecurityContext.setToken(accessToken);
    when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeTokenUri), any(), any(), any(), anyMap(), anyBoolean()))
        .thenThrow(new OAuth2ServiceException("boom", null));

    final Token result = cut.resolveIdToken(null);

    assertThat(result).isNull();
  }

  @Test
  public void resolveIdToken_accessTokenWithEmptyAudience_treatedAsToken_noServiceCall() {
    Token t = new MockTokenBuilder().build();
    when(t.getClaimAsStringList("aud")).thenReturn(java.util.Collections.emptyList());
    when(t.getClientId()).thenReturn(clientId);
    SecurityContext.setToken(t);

    final Token result = cut.resolveIdToken(null);

    assertThat(result).isSameAs(t);
    verifyNoInteractions(tokenService);
  }
}
