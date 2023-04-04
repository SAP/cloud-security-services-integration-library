/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.logging.log4j.ThreadContext.isEmpty;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.io.IOException;

import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.util.HttpClientTestFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class XsuaaTokenAuthenticatorTest {

	private final static HttpServletResponse HTTP_RESPONSE = Mockito.mock(HttpServletResponse.class);

	private final XsuaaToken xsuaaToken;
	private final XsuaaToken invalidToken;
	private final XsuaaToken uaaToken;
	private static CloseableHttpClient mockHttpClient;
	private static final ValidationListener validationListener2 = Mockito.mock(ValidationListener.class);
	private static final ValidationListener validationListener1 = Mockito.mock(ValidationListener.class);
	private static OAuth2ServiceConfigurationBuilder oAuth2ServiceConfigBuilder;
	private static AbstractTokenAuthenticator cut;


	XsuaaTokenAuthenticatorTest() throws IOException {
		xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8));
		invalidToken = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", UTF_8));
		uaaToken = new XsuaaToken(IOUtils.resourceToString("/uaaAccessTokenRSA256.txt", UTF_8));
	}

	@BeforeAll
	static void setUp() throws IOException {
		mockHttpClient = Mockito.mock(CloseableHttpClient.class);

		CloseableHttpResponse xsuaaTokenKeysResponse = HttpClientTestFactory
				.createHttpResponse(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));
		when(mockHttpClient.execute(any(HttpGet.class), any(ResponseHandler.class)))
				.thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(xsuaaTokenKeysResponse);
		});

		CloseableHttpResponse xsuaaTokenResponse = HttpClientTestFactory
				.createHttpResponse(
						"{ \"access_token\": \"" + IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8)
								+ "\", \"expires_in\" : 43199}");
		when(mockHttpClient.execute(any(HttpPost.class))).thenReturn(xsuaaTokenResponse);

		oAuth2ServiceConfigBuilder = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withDomains("auth.com")
				.withProperty(ServiceConstants.XSUAA.APP_ID, "appId")
				.withClientId("clientId")
				.withClientSecret("mySecret")
				.withUrl("https://myauth.com");

		cut = new XsuaaTokenAuthenticator()
				.withHttpClient(mockHttpClient)
				.withValidationListener(validationListener1)
				.withValidationListener(validationListener2)
				.withServiceConfiguration(oAuth2ServiceConfigBuilder.build());
	}

	@Test
	void validateXsuaaToken_WhenConfigurationIsNull() {
		AbstractTokenAuthenticator cut = new XsuaaTokenAuthenticator();

		HttpServletRequest httpRequest = createRequestWithToken(xsuaaToken.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);
		assertFalse(response.isAuthenticated());
		assertTrue(response.getUnauthenticatedReason().contains("Unexpected error occurred: There must be a service configuration."));
	}

	@Test
	void validateUaaToken() {
		HttpServletRequest httpRequest = createRequestWithToken(uaaToken.getTokenValue());

		cut = new XsuaaTokenAuthenticator()
				.withHttpClient(mockHttpClient)
				.withServiceConfiguration(oAuth2ServiceConfigBuilder.withClientId("dashboard_client-Id").build());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason(), isEmpty());
		assertTrue(response.isAuthenticated());
		assertSame(response.getToken(), SecurityContext.getToken());
		assertEquals(Service.XSUAA, response.getToken().getService());
	}

	@Test
	void validateRequest_noHeader_isUnauthenticated() {
		HttpServletRequest httpRequest = createRequestWithoutToken();

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertFalse(response.isAuthenticated());
		assertTrue(response.getUnauthenticatedReason().contains("Authorization header is missing"));
	}

	@Test
	void validateRequest_invalidToken_isUnauthenticated() {
		String errorMessage = "JWT token does not consist of 'header'.'payload'.'signature'";
		HttpServletRequest httpRequest = createRequestWithToken("Bearer invalid");

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertFalse(response.isAuthenticated());
		assertTrue(response.getUnauthenticatedReason().contains(errorMessage));
	}

	@Test
	void validateRequest_validToken_containedInSecurityContext() {
		HttpServletRequest httpRequest = createRequestWithToken(xsuaaToken.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason(), isEmpty());
		assertTrue(response.isAuthenticated());
		assertSame(response.getToken(), SecurityContext.getToken());
		assertEquals(Service.XSUAA, response.getToken().getService());
		assertFalse(((XsuaaToken) response.getToken()).hasLocalScope("test"));
	}

	@Test
	void validateRequest_validToken_listenerIsCalled() {
		HttpServletRequest httpRequest = createRequestWithToken(xsuaaToken.getTokenValue());

		cut.validateRequest(httpRequest, HTTP_RESPONSE);

		Mockito.verify(validationListener1, times(1)).onValidationSuccess();
		Mockito.verify(validationListener2, times(1)).onValidationSuccess();
		Mockito.verifyNoMoreInteractions(validationListener1);
		Mockito.verifyNoMoreInteractions(validationListener2);
	}

	@Test
	void validateRequest_invalidToken_listenerIsCalled() {
		HttpServletRequest httpRequest = createRequestWithToken(invalidToken.getTokenValue());

		cut.validateRequest(httpRequest, HTTP_RESPONSE);

		Mockito.verify(validationListener1, times(1)).onValidationError(any());
		Mockito.verify(validationListener2, times(1)).onValidationError(any());
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
