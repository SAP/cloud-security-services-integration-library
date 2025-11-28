package com.sap.cloud.security.xsuaa.client;

import static org.junit.Assert.assertNull;
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
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import java.net.URI;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class DefaultXsuaaTokenExtensionTest {

  @Mock private OAuth2TokenService tokenService;
  @Mock private Token idToken;
  @Mock private Token xsuaaToken;
  @Mock private OAuth2ServiceConfiguration xsuaaConfig;
  @Mock private URI certUrl;
  @Mock private URI baseUri;
  @Mock private OAuth2TokenResponse response;

  private DefaultXsuaaTokenExtension cut;

  @Before
  public void setUp() throws Exception {
    cut = new DefaultXsuaaTokenExtension(tokenService, xsuaaConfig);
    when(xsuaaConfig.getProperty("certificate")).thenReturn("CERT");
    when(xsuaaConfig.getProperty("key")).thenReturn("KEY");
    when(xsuaaConfig.getClientId()).thenReturn("CLIENT_ID");
    when(idToken.getTokenValue()).thenReturn("TOKEN");
    when(idToken.getClaimAsString("app_tid")).thenReturn("APP_TID");
    when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            any(), any(), any(), any(), any(Boolean.class), any()))
        .thenReturn(response);
  }

  @Test
  public void exchangeToXsuaa_noIDTokenPresent_returnsNull() {
    assertNull(cut.resolveXsuaaToken());
  }

  @Test(expected = IllegalStateException.class)
  public void exchangeToXsuaa_noAPP_TIDPresent_throwsIllegalStateException() {
    try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
      securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
      when(idToken.getClaimAsString("app_tid")).thenReturn(null);

      cut.resolveXsuaaToken();
    }
  }

  @Test
  public void exchangeToXsuaa_errorDuringTokenRetrieval_returnsNull()
      throws OAuth2ServiceException {

    try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
      securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
      when(xsuaaConfig.getCredentialType()).thenReturn(CredentialType.X509);
      when(xsuaaConfig.getCertUrl()).thenReturn(certUrl);
      when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
              any(), any(), any(), any(), any(Boolean.class), any()))
          .thenThrow(OAuth2ServiceException.class);

      assertNull(cut.resolveXsuaaToken());
    }
  }

  @Test
  public void exchangeToXsuaa_configIsCertificateBased_callsEndpointWithCertificateIdentity()
      throws OAuth2ServiceException {

    try (MockedStatic<Token> token = mockStatic(Token.class)) {
      try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
        securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
      token.when(() -> Token.create("TOKEN")).thenReturn(xsuaaToken);
      when(xsuaaConfig.getCredentialType()).thenReturn(CredentialType.X509);
      when(xsuaaConfig.getCertUrl()).thenReturn(certUrl);

        cut.resolveXsuaaToken();

      verify(tokenService, times(1))
          .retrieveAccessTokenViaJwtBearerTokenGrant(
              any(), any(ClientCertificate.class), eq("TOKEN"), any(), eq(false), eq("APP_TID"));
      }
    }
  }

  @Test
  public void exchangeToXsuaa_configIsCredentialsBased_callsEndpointWithCredentialsIdentity()
      throws OAuth2ServiceException {

    try (MockedStatic<Token> token = mockStatic(Token.class)) {
      try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
        securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
        token.when(() -> Token.create("TOKEN")).thenReturn(xsuaaToken);
      when(xsuaaConfig.getCredentialType()).thenReturn(CredentialType.BINDING_SECRET);
      when(xsuaaConfig.getUrl()).thenReturn(baseUri);

        cut.resolveXsuaaToken();

      verify(tokenService, times(1))
          .retrieveAccessTokenViaJwtBearerTokenGrant(
              any(), any(ClientCredentials.class), eq("TOKEN"), any(), eq(false), eq("APP_TID"));
    }
    }
  }
}
