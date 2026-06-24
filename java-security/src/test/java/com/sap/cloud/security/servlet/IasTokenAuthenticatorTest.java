/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;

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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
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

		SecurityHttpClient httpClientMock = Mockito.mock(SecurityHttpClient.class);

		SecurityHttpResponse oidcResponse = HttpClientTestFactory
				.createHttpResponse("{\"jwks_uri\" : \"https://application.auth.com/oauth2/certs\"}");
		SecurityHttpResponse tokenKeysResponse = HttpClientTestFactory
				.createHttpResponse(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));
		when(httpClientMock.execute(any(SecurityHttpRequest.class)))
				.thenReturn(oidcResponse)
				.thenReturn(tokenKeysResponse);

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
		assertTrue(response.getUnauthenticatedReason()
				.contains("Unexpected error occurred: There must be a service configuration."));
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

		assertThat(response.getUnauthenticatedReason()).isEmpty();
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

	@Test
	void withValidatorCustomizer_invokesCustomizerBeforeBuild() {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withDomains("myauth.com")
				.withClientId("T000310")
				.build();
		java.util.concurrent.atomic.AtomicBoolean called = new java.util.concurrent.atomic.AtomicBoolean();

		AbstractTokenAuthenticator authenticator = new IasTokenAuthenticator()
				.withServiceConfiguration(configuration)
				.withValidatorCustomizer(builder -> {
					called.set(true);
					builder.disableTenantIdCheck();
				});
		authenticator.getOrCreateTokenValidator();

		assertTrue(called.get(), "registered customizer must be invoked during validator construction");
	}

	@Test
	void withValidatorCustomizer_multipleCustomizers_areInvokedInOrder() {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withDomains("myauth.com")
				.withClientId("T000310")
				.build();
		java.util.List<Integer> calls = new java.util.ArrayList<>();

		AbstractTokenAuthenticator authenticator = new IasTokenAuthenticator()
				.withServiceConfiguration(configuration)
				.withValidatorCustomizer(b -> calls.add(1))
				.withValidatorCustomizer(b -> calls.add(2));
		authenticator.getOrCreateTokenValidator();

		assertEquals(java.util.List.of(1, 2), calls);
	}

	@Test
	void withValidatorCustomizer_nullCustomizer_throws() {
		assertThrows(NullPointerException.class,
				() -> new IasTokenAuthenticator().withValidatorCustomizer(null));
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
