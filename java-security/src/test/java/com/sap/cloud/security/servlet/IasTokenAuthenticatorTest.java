/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.util.HttpClientTestFactory;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.logging.log4j.ThreadContext.isEmpty;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

class IasTokenAuthenticatorTest {

	private final static HttpServletResponse HTTP_RESPONSE = Mockito.mock(HttpServletResponse.class);
	private static ValidationListener validationListener1;
	private static ValidationListener validationListener2;
	private final SapIdToken token;
	private static AbstractTokenAuthenticator cut;

	IasTokenAuthenticatorTest() throws IOException {
		token = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
	}

	@BeforeAll
	static void setUp() throws IOException {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withDomains("myauth.com")
				.withClientId("T000310")
				.build();

		validationListener1 = Mockito.mock(ValidationListener.class);
		validationListener2 = Mockito.mock(ValidationListener.class);

		CloseableHttpClient httpClientMock = Mockito.mock(CloseableHttpClient.class);

		CloseableHttpResponse oidcResponse = HttpClientTestFactory
				.createHttpResponse("{\"jwks_uri\" : \"https://application.auth.com/oauth2/certs\"}");
		CloseableHttpResponse tokenKeysResponse = HttpClientTestFactory
				.createHttpResponse(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));
		when(httpClientMock.execute(any(HttpGet.class), any(HttpClientResponseHandler.class)))
				.thenAnswer(invocation -> {
					HttpClientResponseHandler responseHandler = invocation.getArgument(1);
					return responseHandler.handleResponse(oidcResponse);
				})
				.thenAnswer(invocation -> {
					HttpClientResponseHandler responseHandler = invocation.getArgument(1);
					return responseHandler.handleResponse(tokenKeysResponse);
				});

		cut = new IasTokenAuthenticator()
				.withServiceConfiguration(configuration)
				.withHttpClient(httpClientMock)
				.withValidationListener(validationListener1)
				.withValidationListener(validationListener2);
	}

	@Test
	void validateWhenConfigurationIsNull() {
		AbstractTokenAuthenticator cut = new IasTokenAuthenticator();

		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);
		assertFalse(response.isAuthenticated());
		assertTrue(response.getUnauthenticatedReason().contains("Unexpected error occurred: There must be a service configuration."));
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
		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason(), isEmpty());
		assertTrue(response.isAuthenticated());
		assertSame(response.getToken(), SecurityContext.getToken());
	}

	@Test
	void validateRequest_listenerIsCalled() {
		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue());

		cut.validateRequest(httpRequest, HTTP_RESPONSE);

		Mockito.verify(validationListener1, times(2)).onValidationSuccess();
		Mockito.verify(validationListener2, times(2)).onValidationSuccess();
		Mockito.verifyNoMoreInteractions(validationListener1);
		Mockito.verifyNoMoreInteractions(validationListener2);
	}

	@Test
	void validateRequest_invalidToken_listenerIsCalled() {
		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue() + "B");

		cut.validateRequest(httpRequest, HTTP_RESPONSE);

		Mockito.verify(validationListener1, times(1)).onValidationError(any());
		Mockito.verify(validationListener2, times(1)).onValidationError(any());
	}

	private HttpServletRequest createRequestWithoutToken() {
		return Mockito.mock(HttpServletRequest.class);
	}

	private HttpServletRequest createRequestWithToken(String bearerAuthorizationHeader) {
		HttpServletRequest httpRequest = createRequestWithoutToken();
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + bearerAuthorizationHeader);
		return httpRequest;
	}

}
