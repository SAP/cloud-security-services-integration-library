package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.util.HttpClientTestFactory;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.github.stefanbirkner.systemlambda.SystemLambda.withEnvironmentVariable;
import static com.sap.cloud.security.config.cf.CFConstants.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class XsuaaTokenAuthenticatorTest {

	private final static HttpServletResponse HTTP_RESPONSE = Mockito.mock(HttpServletResponse.class);

	private final XsuaaToken xsuaaToken;
	private final XsuaaToken invalidSignatureToken;
	private final SapIdToken iasToken;
	private CloseableHttpClient mockHttpClient;
	private OAuth2ServiceConfiguration oAuth2ServiceConfiguration;

	private AbstractTokenAuthenticator cut;

	public XsuaaTokenAuthenticatorTest() throws IOException {
		xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaUserAccessTokenRSA256.txt", UTF_8));
		invalidSignatureToken = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaInvalidSignatureTokenRSA256.txt", UTF_8));
		iasToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
	}

	@Before
	public void setUp() throws IOException {
		mockHttpClient = Mockito.mock(CloseableHttpClient.class);

		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));
		when(mockHttpClient.execute(any(HttpGet.class))).thenReturn(response);

		oAuth2ServiceConfiguration = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withProperty(XSUAA.UAA_DOMAIN, "auth.com")
				.withProperty(XSUAA.APP_ID, "appId")
				.withClientId("clientId")
				.withClientSecret("mySecret")
				.withUrl("https://myauth.com")
				.build();

		cut = new XsuaaTokenAuthenticator()
				.withHttpClient(mockHttpClient)
				.withServiceConfiguration(oAuth2ServiceConfiguration);
	}

	@Test
	public void validateWhenConfigurationIsNull() {
		cut = new XsuaaTokenAuthenticator();

		HttpServletRequest httpRequest = createRequestWithToken(xsuaaToken.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);
		assertThat(response.isAuthenticated()).isFalse();
		assertThat(response.getUnauthenticatedReason())
				.contains("Unexpected error occurred: There must be a service configuration.");
	}

	@Test
	public void validateRequest_noHeader_isUnauthenticated() {
		HttpServletRequest httpRequest = createRequestWithoutToken();

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.isAuthenticated()).isFalse();
		assertThat(response.getUnauthenticatedReason()).contains("Authorization header is missing");
	}

	@Test
	public void validateRequest_invalidToken_isUnauthenticated() {
		String errorMessage = "JWT token does not consist of 'header'.'payload'.'signature'";
		HttpServletRequest httpRequest = createRequestWithToken("Bearer invalid");

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.isAuthenticated()).isFalse();
		assertThat(response.getUnauthenticatedReason()).contains(errorMessage);
	}

	@Test
	public void validateRequest_validToken_containedInSecurityContext() {
		HttpServletRequest httpRequest = createRequestWithToken(xsuaaToken.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason()).isEmpty();
		assertThat(response.isAuthenticated()).isTrue();
		assertThat(response.getToken()).isSameAs(SecurityContext.getToken());
		assertThat(response.getToken().getService()).isEqualTo(Service.XSUAA);
		assertThat(((XsuaaToken) response.getToken()).hasLocalScope("test")).isFalse();
	}

	@Test
	public void validateRequest_validToken_listenerIsCalled() {
		HttpServletRequest httpRequest = createRequestWithToken(xsuaaToken.getTokenValue());
		ValidationListener validationListener1 = Mockito.mock(ValidationListener.class);
		ValidationListener validationListener2 = Mockito.mock(ValidationListener.class);

		cut.withValidationListener(validationListener1)
				.withValidationListener(validationListener2)
				.validateRequest(httpRequest, HTTP_RESPONSE);

		Mockito.verify(validationListener1, times(1)).onValidationSuccess();
		Mockito.verify(validationListener2, times(1)).onValidationSuccess();
		Mockito.verifyNoMoreInteractions(validationListener1);
		Mockito.verifyNoMoreInteractions(validationListener2);
	}

	@Test
	public void validateRequest_invalidToken_listenerIsCalled() {
		HttpServletRequest httpRequest = createRequestWithToken(invalidSignatureToken.getTokenValue());
		ValidationListener validationListener1 = Mockito.mock(ValidationListener.class);
		ValidationListener validationListener2 = Mockito.mock(ValidationListener.class);

		cut.withValidationListener(validationListener1)
				.withValidationListener(validationListener2)
				.validateRequest(httpRequest, HTTP_RESPONSE);

		Mockito.verify(validationListener1, times(1)).onValidationError(any());
		Mockito.verify(validationListener2, times(1)).onValidationError(any());
		Mockito.verifyNoMoreInteractions(validationListener2);
		Mockito.verifyNoMoreInteractions(validationListener2);
	}

	@Test
	public void validateRequest_tokenXchangeEnabled_IasToken() throws Exception {
		IasXsuaaExchangeBroker mockExchangeBroker = Mockito.mock(IasXsuaaExchangeBroker.class);
		when(mockExchangeBroker.doIasToXsuaaXchange(any(), any(), any())).thenReturn(xsuaaToken.getTokenValue());

		cut = new XsuaaTokenAuthenticator(mockExchangeBroker)
				.withHttpClient(mockHttpClient)
				.withServiceConfiguration(oAuth2ServiceConfiguration);

		HttpServletRequest httpRequest = createRequestWithToken(iasToken.getTokenValue());
		final TokenAuthenticationResult[] response = new TokenAuthenticationResult[1];
		withEnvironmentVariable("IAS_XSUAA_XCHANGE_ENABLED", "true")
				.execute(() -> response[0] = cut.validateRequest(httpRequest, HTTP_RESPONSE));
		assertEquals(response[0].getToken(), xsuaaToken);

	}

	@Test
	public void validateRequest_tokenXchangeEnabled_IasTokenXchangeBrokerError() throws Exception {
		IasXsuaaExchangeBroker mockExchangeBroker = Mockito.mock(IasXsuaaExchangeBroker.class);
		when(mockExchangeBroker.doIasToXsuaaXchange(any(), any(), any())).thenThrow(TokenFlowException.class);

		cut = new XsuaaTokenAuthenticator(mockExchangeBroker)
				.withHttpClient(mockHttpClient)
				.withServiceConfiguration(oAuth2ServiceConfiguration);

		HttpServletRequest httpRequest = createRequestWithToken(iasToken.getTokenValue());
		final TokenAuthenticationResult[] response = new TokenAuthenticationResult[1];
		withEnvironmentVariable("IAS_XSUAA_XCHANGE_ENABLED", "true")
				.execute(() -> response[0] = cut.validateRequest(httpRequest, HTTP_RESPONSE));
		assertFalse(response[0].isAuthenticated());
	}

	@Test
	public void validateRequest_tokenXchangeEnabled_validXsuaa() throws Exception {
		IasXsuaaExchangeBroker mockExchangeBroker = Mockito.mock(IasXsuaaExchangeBroker.class);
		when(mockExchangeBroker.doIasToXsuaaXchange(any(), any(), any())).thenReturn(xsuaaToken.getTokenValue());

		cut = new XsuaaTokenAuthenticator(mockExchangeBroker)
				.withHttpClient(mockHttpClient)
				.withServiceConfiguration(oAuth2ServiceConfiguration);

		HttpServletRequest httpRequest = createRequestWithToken(xsuaaToken.getTokenValue());
		final TokenAuthenticationResult[] response = new TokenAuthenticationResult[1];
		withEnvironmentVariable("IAS_XSUAA_XCHANGE_ENABLED", "true")
				.execute(() -> response[0] = cut.validateRequest(httpRequest, HTTP_RESPONSE));
		assertEquals(response[0].getToken(), xsuaaToken);
	}

	@Test
	public void validateRequest_tokenXchangeEnabled_invalidXsuaa() throws Exception {
		IasXsuaaExchangeBroker mockExchangeBroker = Mockito.mock(IasXsuaaExchangeBroker.class);
		when(mockExchangeBroker.doIasToXsuaaXchange(any(), any(), any())).thenThrow(TokenFlowException.class);

		cut = new XsuaaTokenAuthenticator(mockExchangeBroker)
				.withHttpClient(mockHttpClient)
				.withServiceConfiguration(oAuth2ServiceConfiguration);

		HttpServletRequest httpRequest = createRequestWithToken(invalidSignatureToken.getTokenValue());
		final TokenAuthenticationResult[] response = new TokenAuthenticationResult[1];
		withEnvironmentVariable("IAS_XSUAA_XCHANGE_ENABLED", "true")
				.execute(() -> response[0] = cut.validateRequest(httpRequest, HTTP_RESPONSE));
		assertFalse(response[0].isAuthenticated());
	}

	@Test
	public void validateRequest_tokenXchangeFalse_validXsuaa() throws Exception {

		IasXsuaaExchangeBroker mockExchangeBroker = Mockito.mock(IasXsuaaExchangeBroker.class);
		when(mockExchangeBroker.doIasToXsuaaXchange(any(), any(), any())).thenReturn(xsuaaToken.getTokenValue());

		cut = new XsuaaTokenAuthenticator(mockExchangeBroker)
				.withHttpClient(mockHttpClient)
				.withServiceConfiguration(oAuth2ServiceConfiguration);

		HttpServletRequest httpRequest = createRequestWithToken(xsuaaToken.getTokenValue());
		final TokenAuthenticationResult[] response = new TokenAuthenticationResult[1];
		withEnvironmentVariable("IAS_XSUAA_XCHANGE_ENABLED", "false")
				.execute(() -> response[0] = cut.validateRequest(httpRequest, HTTP_RESPONSE));
		assertTrue(response[0].isAuthenticated());
	}

	@Test
	public void validateRequest_tokenXchangeFalse_invalidXsuaa() throws Exception {
		IasXsuaaExchangeBroker mockExchangeBroker = Mockito.mock(IasXsuaaExchangeBroker.class);
		when(mockExchangeBroker.doIasToXsuaaXchange(any(), any(), any())).thenThrow(TokenFlowException.class);

		cut = new XsuaaTokenAuthenticator(mockExchangeBroker)
				.withHttpClient(mockHttpClient)
				.withServiceConfiguration(oAuth2ServiceConfiguration);

		HttpServletRequest httpRequest = createRequestWithToken(invalidSignatureToken.getTokenValue());
		final TokenAuthenticationResult[] response = new TokenAuthenticationResult[1];
		withEnvironmentVariable("IAS_XSUAA_XCHANGE_ENABLED", "false")
				.execute(() -> response[0] = cut.validateRequest(httpRequest, HTTP_RESPONSE));
		assertFalse(response[0].isAuthenticated());
	}

	private HttpServletRequest createRequestWithoutToken() {
		return Mockito.mock(HttpServletRequest.class);
	}

	private HttpServletRequest createRequestWithToken(String jwtToken) {
		HttpServletRequest httpRequest = createRequestWithoutToken();
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + jwtToken);
		return httpRequest;
	}

}
