package com.sap.cloud.security.xsuaa.client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.CredentialType;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import java.net.URI;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaTokenExchangeServiceTest {

  @Mock private OAuth2TokenService tokenService;
  @Mock private Token idToken;
  @Mock private Token xsuaaToken;
  @Mock private OAuth2ServiceConfiguration xsuaaConfig;
  @Mock private URI certUrl;
  @Mock private URI baseUri;
  @Mock private OAuth2TokenResponse response;

  private XsuaaTokenExchangeService cut;

  @Before
  public void setUp() throws Exception {
    cut = new XsuaaTokenExchangeService();
    when(xsuaaConfig.getProperty("certificate")).thenReturn("CERT");
    when(xsuaaConfig.getProperty("key")).thenReturn("KEY");
    when(xsuaaConfig.getClientId()).thenReturn("CLIENT_ID");
    when(idToken.getTokenValue()).thenReturn("TOKEN");
    when(idToken.getClaimAsString("app_tid")).thenReturn("APP_TID");
    when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            any(), any(), any(), any(), any(Boolean.class), any()))
        .thenReturn(response);
  }

  @Test(expected = IllegalStateException.class)
  public void exchangeToXsuaa_noAPP_TIDPresent_throwsIllegalStateException()
      throws OAuth2ServiceException {
    when(idToken.getClaimAsString("app_tid")).thenReturn(null);

    cut.exchangeToXsuaa(idToken, xsuaaConfig, tokenService);
  }

  @Test
  public void exchangeToXsuaa_configIsCertificateBased_callsEndpointWithCertificateIdentity()
      throws OAuth2ServiceException {

    try (MockedStatic<Token> token = mockStatic(Token.class)) {
      token.when(() -> Token.create("TOKEN")).thenReturn(xsuaaToken);
      when(xsuaaConfig.getCredentialType()).thenReturn(CredentialType.X509);
      when(xsuaaConfig.getCertUrl()).thenReturn(certUrl);

      cut.exchangeToXsuaa(idToken, xsuaaConfig, tokenService);

      verify(tokenService, times(1))
          .retrieveAccessTokenViaJwtBearerTokenGrant(
              any(), any(ClientCertificate.class), eq("TOKEN"), any(), eq(false), eq("APP_TID"));
    }
  }

  @Test
  public void exchangeToXsuaa_configIsCredentialsBased_callsEndpointWithCredentialsIdentity()
      throws OAuth2ServiceException {

    try (MockedStatic<Token> token = mockStatic(Token.class)) {
      token.when(() -> Token.create("TOKEN")).thenReturn(xsuaaToken);
      when(xsuaaConfig.getCredentialType()).thenReturn(CredentialType.BINDING_SECRET);
      when(xsuaaConfig.getUrl()).thenReturn(baseUri);

      cut.exchangeToXsuaa(idToken, xsuaaConfig, tokenService);

      verify(tokenService, times(1))
          .retrieveAccessTokenViaJwtBearerTokenGrant(
              any(), any(ClientCredentials.class), eq("TOKEN"), any(), eq(false), eq("APP_TID"));
    }
  }
}
