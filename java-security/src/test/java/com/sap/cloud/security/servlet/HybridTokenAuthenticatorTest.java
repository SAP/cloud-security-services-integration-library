package com.sap.cloud.security.servlet;

import static com.sap.cloud.security.token.TokenExchangeMode.DISABLED;
import static com.sap.cloud.security.token.TokenExchangeMode.FORCE_XSUAA;
import static com.sap.cloud.security.token.TokenExchangeMode.PROVIDE_XSUAA;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.TokenExchangeMode;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class HybridTokenAuthenticatorTest {

  @Mock private IasTokenAuthenticator iasAuthenticator;
  @Mock private XsuaaTokenAuthenticator xsuaaAuthenticator;
  @Mock private HttpServletRequest httpReq;
  @Mock private HttpServletResponse httpResp;
  @Mock private TokenAuthenticationResult authenticationResult;
  @Mock private CloseableHttpClient httpClientMock;
  @Mock private OAuth2ServiceConfiguration iasConfig;
  @Mock private OAuth2ServiceConfiguration xsuaaConfig;

  private final SapIdToken accessToken;
  private final SapIdToken idToken;
  private final XsuaaToken xsuaaToken;
  private final SapIdToken invalidToken;

  private HybridTokenAuthenticator cut;

  public HybridTokenAuthenticatorTest() throws IOException {
    accessToken = new SapIdToken(IOUtils.resourceToString("/iasTokenWithCnfRSA256.txt", UTF_8));
    xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8));
    invalidToken = new SapIdToken(IOUtils.resourceToString("/iasTokenInvalidCnfRSA256.txt", UTF_8));
    idToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
  }

  @BeforeEach
  public void setUp() throws Exception {
    setupClassUnderTesting(DISABLED);
  }

  @Test
  public void returnsUnauthenticated_whenRequestIsNotHttp() {
    ServletRequest nonHttpReq = mock(ServletRequest.class);

    TokenAuthenticationResult result = cut.validateRequest(nonHttpReq, httpResp);

    assertThat(result.isAuthenticated()).isFalse();
    assertThat(result.getUnauthenticatedReason()).contains("Could not process request");
  }

  @Test
  public void returnsUnauthenticated_whenResponseIsNotHttp() {
    ServletResponse nonHttpResp = mock(ServletResponse.class);

    TokenAuthenticationResult result = cut.validateRequest(httpReq, nonHttpResp);

    assertThat(result.isAuthenticated()).isFalse();
    assertThat(result.getUnauthenticatedReason()).contains("Could not process request");
  }

  @Test
  public void returnsUnauthenticated_whenRequestIsNull() {
    TokenAuthenticationResult result = cut.validateRequest(null, httpResp);

    assertThat(result.isAuthenticated()).isFalse();
    assertThat(result.getUnauthenticatedReason()).contains("Could not process request");
  }

  @Test
  public void returnsUnauthenticated_whenResponseIsNull() {
    TokenAuthenticationResult result = cut.validateRequest(httpReq, null);

    assertThat(result.isAuthenticated()).isFalse();
    assertThat(result.getUnauthenticatedReason()).contains("Could not process request");
  }

  @Test
  public void validateRequest_noHeader_isUnauthenticated() {
    createRequestWithoutToken();

    TokenAuthenticationResult response = cut.validateRequest(httpReq, httpResp);

    assertThat(response.isAuthenticated()).isFalse();
    assertThat(response.getUnauthenticatedReason()).contains("Authorization header is missing");
  }

  @Test
  public void validateRequest_invalidToken_isUnauthenticated() {
    createRequestWithBearerHeader("invalid"); // pass token VALUE only

    TokenAuthenticationResult response = cut.validateRequest(httpReq, httpResp);

    assertThat(response.isAuthenticated()).isFalse();
    assertThat(response.getUnauthenticatedReason())
        .contains("JWT token does not consist of 'header'.'payload'.'signature'");
  }

  @Test
  public void validateRequest_tokenIsAlreadyXSUAA_callsXsuaaAuthenticator() {
    when(authenticationResult.isAuthenticated()).thenReturn(true);
    createRequestWithBearerHeader(xsuaaToken.getTokenValue());

    TokenAuthenticationResult response = cut.validateRequest(httpReq, httpResp);

    verify(xsuaaAuthenticator, times(1)).validateRequest(httpReq, httpResp);
    assertThat(SecurityContext.getXsuaaToken()).isEqualTo(response.getToken());
    assertThat(response.isAuthenticated()).isTrue();
  }

  @Test
  public void validateRequest_invalidIasToken_returnsUnauthenticated() {
    when(authenticationResult.isAuthenticated()).thenReturn(false);
    createRequestWithBearerHeader(invalidToken.getTokenValue());

    TokenAuthenticationResult response = cut.validateRequest(httpReq, httpResp);

    verify(iasAuthenticator, times(1)).validateRequest(httpReq, httpResp);
    assertThat(response.isAuthenticated()).isFalse();
  }

  @Test
  public void validateRequest_validIasToken_butExceptionOnTokenExchange_returnsUnauthenticated()
      throws Exception {
    setupClassUnderTesting(FORCE_XSUAA);
    when(authenticationResult.isAuthenticated()).thenReturn(true);
    createRequestWithBearerHeader(accessToken.getTokenValue());

    try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
      securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
      securityContext
          .when(SecurityContext::getXsuaaToken)
          .thenThrow(IllegalArgumentException.class);

      TokenAuthenticationResult response = cut.validateRequest(httpReq, httpResp);

      assertThat(response.isAuthenticated()).isFalse();
      assertThat(response.getUnauthenticatedReason())
          .contains("Unexpected error during exchange from ID token to XSUAA token:");
    }
  }

  @Test
  public void validateRequest_forceXsuaaMode_returnsAuthenticatedXSUAAResult() throws Exception {
    setupClassUnderTesting(FORCE_XSUAA);
    when(authenticationResult.isAuthenticated()).thenReturn(true);
    createRequestWithBearerHeader(accessToken.getTokenValue());

    try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
      securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
      securityContext.when(SecurityContext::getXsuaaToken).thenReturn(xsuaaToken);

      cut.validateRequest(httpReq, httpResp);

      verify(xsuaaAuthenticator, times(1)).authenticated(xsuaaToken);
      securityContext.verify(SecurityContext::getXsuaaToken);
      securityContext.verify(() -> SecurityContext.updateToken(xsuaaToken));
    }
  }

  @Test
  public void validateRequest_provideXsuaaMode_returnsAuthenticatedIASResult() throws Exception {
    setupClassUnderTesting(PROVIDE_XSUAA);
    when(authenticationResult.isAuthenticated()).thenReturn(true);
    createRequestWithBearerHeader(accessToken.getTokenValue());

    try (MockedStatic<SecurityContext> securityContext = mockStatic(SecurityContext.class)) {
      securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
      securityContext.when(SecurityContext::getXsuaaToken).thenReturn(xsuaaToken);

      TokenAuthenticationResult response = cut.validateRequest(httpReq, httpResp);

      verify(xsuaaAuthenticator, never()).authenticated(any());
      securityContext.verify(SecurityContext::getXsuaaToken);
      assertThat(response.isAuthenticated()).isTrue();
    }
  }

  @Test
  public void validateRequest_tokenExchangeDisabled_returnsAuthenticatedIASResult() {
    when(authenticationResult.isAuthenticated()).thenReturn(true);
    createRequestWithBearerHeader(accessToken.getTokenValue());

    TokenAuthenticationResult response = cut.validateRequest(httpReq, httpResp);

    verify(xsuaaAuthenticator, never()).authenticated(any());
    assertThat(SecurityContext.getXsuaaToken()).isNull();
    assertThat(response.isAuthenticated()).isTrue();
  }

  @Test
  public void getServiceConfiguration_callsXsuaaAuthenticator() {
    cut.getServiceConfiguration();
    verify(xsuaaAuthenticator, times(1)).getServiceConfiguration();
  }

  @Test
  public void getOtherServiceConfiguration_callsXsuaaAuthenticator() {
    cut.getOtherServiceConfiguration();
    verify(xsuaaAuthenticator, times(1)).getOtherServiceConfiguration();
  }

  @Test
  public void extractFromHeader_callsXsuaaAuthenticator() {
    createRequestWithBearerHeader(accessToken.getTokenValue());

    cut.extractFromHeader(httpReq.getHeader(HttpHeaders.AUTHORIZATION));

    verify(xsuaaAuthenticator, times(1))
        .extractFromHeader(httpReq.getHeader(HttpHeaders.AUTHORIZATION));
  }

  private void setupClassUnderTesting(final TokenExchangeMode mode) throws Exception {
    cut = new HybridTokenAuthenticator(iasConfig, httpClientMock, xsuaaConfig, mode);
    setField(cut, "iasTokenAuthenticator", iasAuthenticator);
    setField(cut, "xsuaaTokenAuthenticator", xsuaaAuthenticator);
  }

  private void createRequestWithoutToken() {
    lenient().when(httpReq.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
    lenient().when(iasAuthenticator.validateRequest(httpReq, httpResp)).thenReturn(authenticationResult);
    lenient().when(xsuaaAuthenticator.validateRequest(httpReq, httpResp)).thenReturn(authenticationResult);
  }

  private void createRequestWithBearerHeader(String tokenValue) {
    createRequestWithoutToken();
    when(httpReq.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(bearer(tokenValue));
  }

  private static void setField(Object target, String name, Object value) throws Exception {
    Field f = target.getClass().getDeclaredField(name);
    f.setAccessible(true);
    f.set(target, value);
  }

  private static String bearer(String token) {
    return "Bearer " + token;
  }
}
