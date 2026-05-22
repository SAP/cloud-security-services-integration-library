package com.sap.cloud.security.xsuaa.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class DefaultXsuaaTokenExtensionTest {

  @Mock private OAuth2TokenService tokenService;
  @Mock private Token idToken;
  @Mock private Token xsuaaToken;
  @Mock private OAuth2ServiceConfiguration xsuaaConfig;
  @Mock private URI certUrl;
  @Mock private URI baseUri;
  @Mock private OAuth2TokenResponse response;

  private DefaultXsuaaTokenExtension cut;

  @BeforeEach
  public void setUp() throws Exception {
    cut = new DefaultXsuaaTokenExtension(tokenService, xsuaaConfig);

    // Mock getClientIdentity() to return appropriate ClientIdentity
    ClientCertificate clientCert = new ClientCertificate("CERT", "KEY", "CLIENT_ID");
    lenient().when(xsuaaConfig.getClientIdentity()).thenReturn(clientCert); // default to cert

    lenient().when(xsuaaConfig.getClientId()).thenReturn("CLIENT_ID");
    lenient().when(idToken.getTokenValue()).thenReturn("TOKEN");
    lenient().when(idToken.getClaimAsString("app_tid")).thenReturn("APP_TID");
    lenient().when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
            any(), any(), any(), any(), any(Boolean.class), any()))
        .thenReturn(response);
  }

  @Test
  public void exchangeToXsuaa_noIDTokenPresent_returnsNull() {
    assertThat(cut.resolveXsuaaToken(null)).isNull();
  }

  @Test
  public void exchangeToXsuaa_noAPP_TIDPresent_throwsIllegalStateException() {
    try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
      securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
      when(idToken.getClaimAsString("app_tid")).thenReturn(null);

      assertThatThrownBy(() -> cut.resolveXsuaaToken(null))
          .isInstanceOf(IllegalStateException.class);
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

      assertThat(cut.resolveXsuaaToken(null)).isNull();
    }
  }

  @Test
  public void exchangeToXsuaa_tokenIsAlreadyXSUAA_returnsToken() {
    when(xsuaaToken.isExpired()).thenReturn(false);

    Token result = cut.resolveXsuaaToken(xsuaaToken);

    assertThat(result).isEqualTo(xsuaaToken);
  }

  @Test
  public void getXsuaaToken_tokenIsExpired_exchangesForNewToken() throws OAuth2ServiceException {
    when(xsuaaToken.isExpired()).thenReturn(true);

    try (MockedStatic<Token> token = mockStatic(Token.class)) {
      try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
        securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
        token.when(() -> Token.create("TOKEN")).thenReturn(xsuaaToken);
        when(xsuaaConfig.getCredentialType()).thenReturn(CredentialType.X509);
        when(xsuaaConfig.getCertUrl()).thenReturn(certUrl);

        cut.resolveXsuaaToken(xsuaaToken);

        verify(tokenService, times(1))
            .retrieveAccessTokenViaJwtBearerTokenGrant(
                any(), any(ClientCertificate.class), eq("TOKEN"), any(), eq(false), eq("APP_TID"));
      }
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

        cut.resolveXsuaaToken(null);

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
        when(xsuaaConfig.getClientIdentity()).thenReturn(new ClientCredentials("CLIENT_ID", "SECRET"));
        when(xsuaaConfig.getCredentialType()).thenReturn(CredentialType.BINDING_SECRET);
        when(xsuaaConfig.getUrl()).thenReturn(baseUri);

        cut.resolveXsuaaToken(null);

      verify(tokenService, times(1))
          .retrieveAccessTokenViaJwtBearerTokenGrant(
              any(), any(ClientCredentials.class), eq("TOKEN"), any(), eq(false), eq("APP_TID"));
    }
    }
  }

  @Test
  public void getXsuaaToken_errorDuringTokenExchange_returnNull() throws OAuth2ServiceException {
    when(xsuaaToken.isExpired()).thenReturn(true);

    try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
      securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
      when(xsuaaConfig.getCredentialType()).thenReturn(CredentialType.X509);
      when(xsuaaConfig.getCertUrl()).thenReturn(certUrl);
      when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
              any(), any(ClientCertificate.class), eq("TOKEN"), any(), eq(false), eq("APP_TID")))
          .thenThrow(OAuth2ServiceException.class);

      Token result = cut.resolveXsuaaToken(xsuaaToken);

      assertThat(result).isNull();
    }
  }
}
