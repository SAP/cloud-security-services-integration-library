package com.sap.cloud.security.token;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

public class DefaultIdTokenExtensionTest {

  private final String clientId = "clientId";
  private final URI tokenUri = URI.create("http://localhost:8080");
  private final URI completeTokenUri = URI.create("http://localhost:8080/oauth2/token");
  private final URI certUri = URI.create("http://localhost:8080/cert");
  private final URI completeCertUri = URI.create("http://localhost:8080/cert/oauth2/token");

  private static final Token idToken = new MockTokenBuilder().build();
  private static final Token accessToken = new MockTokenBuilder().build();
  private static final Token technicalUserToken = new MockTokenBuilder().build();
  private static final OAuth2TokenResponse certTokenResponse =
      Mockito.mock(OAuth2TokenResponse.class);
  private static final OAuth2TokenResponse tokenResponse = Mockito.mock(OAuth2TokenResponse.class);
  private DefaultIdTokenExtension cut;
  private final OAuth2TokenService tokenService = Mockito.mock(OAuth2TokenService.class);
  private final OAuth2ServiceConfiguration serviceConfiguration =
      Mockito.mock(OAuth2ServiceConfiguration.class);

  @Before
  public void setUp() throws IOException {
    SecurityContext.clear();
    when(serviceConfiguration.getUrl()).thenReturn(tokenUri);
    when(serviceConfiguration.getClientId()).thenReturn(clientId);
    String clientSecret = "clientSecret";
    when(serviceConfiguration.getClientSecret()).thenReturn(clientSecret);
    when(serviceConfiguration.getCertUrl()).thenReturn(certUri);
    String certPem = "certPem";
    when(serviceConfiguration.getProperty("certificate")).thenReturn(certPem);
    String keyPem = "keyPem";
    when(serviceConfiguration.getProperty("key")).thenReturn(keyPem);
    when(serviceConfiguration.getProperty("clientId")).thenReturn(clientId);
    String audience = "audience";
    when(idToken.getClaimAsStringList("aud")).thenReturn(List.of(audience, clientId));
    when(idToken.getClientId()).thenReturn(clientId);
    when(accessToken.getClaimAsStringList("aud")).thenReturn(List.of(clientId));
    when(accessToken.getClientId()).thenReturn(clientId);
    when(technicalUserToken.getClaimAsString("sub")).thenReturn(clientId);
    when(technicalUserToken.getClientId()).thenReturn(clientId);
    when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeCertUri), any(), any(), any(), anyMap(), anyBoolean()))
        .thenReturn(certTokenResponse);
    when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeTokenUri), any(), any(), any(), anyMap(), anyBoolean()))
        .thenReturn(tokenResponse);
    when(accessToken.getTokenValue())
        .thenReturn(IOUtils.resourceToString("/iasTokenWithCnfRSA256.txt", UTF_8));
    when(tokenResponse.getAccessToken())
        .thenReturn(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
    when(certTokenResponse.getAccessToken())
        .thenReturn(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));

    cut = new DefaultIdTokenExtension(tokenService, serviceConfiguration);
  }

  @Test(expected = IllegalArgumentException.class)
  public void resolveIdToken_noTokenInContext_throwsIllegalArgumentException() {
    cut.resolveIdToken();
  }

  @Test(expected = IllegalArgumentException.class)
  public void resolveIdToken_tokenIsTechnicalUser_throwsIllegalArgumentException() {
    SecurityContext.setToken(technicalUserToken);

    cut.resolveIdToken();
  }

  @Test
  public void resolveIdToken_tokenIsAlreadyIDToken_returnToken() {
    SecurityContext.setToken(idToken);

    final Token result = cut.resolveIdToken();

    assertEquals(idToken, result);
  }

  @Test
  public void resolveIdToken_tokenIsAccessTokenWithCertificate_exchangeTokenForIDTokenWithCert()
      throws OAuth2ServiceException {
    SecurityContext.setToken(accessToken);
    ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Map<String, String>> paramCaptor = ArgumentCaptor.forClass(Map.class);

    final Token result = cut.resolveIdToken();

    verify(tokenService)
        .retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeCertUri),
            any(),
            tokenCaptor.capture(),
            any(),
            paramCaptor.capture(),
            eq(false));
    assertEquals(tokenCaptor.getValue(), accessToken.getTokenValue());
    Map<String, String> params = paramCaptor.getValue();
    assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", params.get("grant_type"));
    assertEquals(accessToken.getTokenValue(), params.get("assertion"));
    assertEquals("jwt", params.get("token_format"));
    assertEquals("0", params.get("refresh_expiry"));
    assertEquals(clientId, params.get("client_id"));
    assertEquals(certTokenResponse.getAccessToken(), result.getTokenValue());
  }

  @Test
  public void
      resolveIdToken_tokenIsAccessTokenWithClientCredentials_exchangeTokenForIDTokenWithClientSecret()
          throws OAuth2ServiceException {
    SecurityContext.setToken(accessToken);
    when(serviceConfiguration.getProperty("certificate")).thenReturn(null);
    when(serviceConfiguration.getProperty("key")).thenReturn(null);
    ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Map<String, String>> paramCaptor = ArgumentCaptor.forClass(Map.class);

    final Token result = cut.resolveIdToken();

    verify(tokenService)
        .retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeTokenUri),
            any(),
            tokenCaptor.capture(),
            any(),
            paramCaptor.capture(),
            eq(false));

    Map<String, String> params = paramCaptor.getValue();
    assertEquals(accessToken.getTokenValue(), tokenCaptor.getValue());
    assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", params.get("grant_type"));
    assertEquals(accessToken.getTokenValue(), params.get("assertion"));
    assertEquals("jwt", params.get("token_format"));
    assertEquals("0", params.get("refresh_expiry"));
    assertEquals(clientId, params.get("client_id"));
    assertEquals(tokenResponse.getAccessToken(), result.getTokenValue());
  }

  @Test
  public void resolveIdToken_tokenIsAlreadyIDToken_doesNotCallTokenService() {
    SecurityContext.setToken(idToken);

    final Token result = cut.resolveIdToken();

    assertSame(idToken, result);
    verifyNoInteractions(tokenService);
  }

  @Test
  public void resolveIdToken_exchangeFails_returnsNull() throws OAuth2ServiceException {
    SecurityContext.setToken(accessToken);
    when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            eq(completeCertUri), any(), any(), any(), anyMap(), anyBoolean()))
        .thenThrow(new OAuth2ServiceException("boom", null));

    final Token result = cut.resolveIdToken();

    assertNull(result);
  }

  @Test
  public void resolveIdToken_accessTokenWithEmptyAudience_treatedAsIdToken_noServiceCall() {
    Token t = new MockTokenBuilder().build();
    when(t.getClaimAsStringList("aud")).thenReturn(java.util.Collections.emptyList());
    when(t.getClientId()).thenReturn(clientId);
    SecurityContext.setToken(t);

    final Token result = cut.resolveIdToken();

    assertSame(t, result);
    verifyNoInteractions(tokenService);
  }
}
