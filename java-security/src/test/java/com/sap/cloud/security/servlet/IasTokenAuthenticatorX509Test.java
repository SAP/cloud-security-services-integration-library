/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.token.validation.validators.JwtX5tValidator;
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

import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyString;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class IasTokenAuthenticatorX509Test {

	private final static HttpServletResponse HTTP_RESPONSE = Mockito.mock(HttpServletResponse.class);

	private final SapIdToken tokenValidX5t;
	private final SapIdToken tokenInvalidX5t;
	private final String x509;

	private static AbstractTokenAuthenticator cut;

	public IasTokenAuthenticatorX509Test() throws IOException {
		tokenValidX5t = new SapIdToken(IOUtils.resourceToString("/iasTokenWithCnfRSA256.txt", UTF_8));
		tokenInvalidX5t = new SapIdToken(IOUtils.resourceToString("/iasTokenInvalidCnfRSA256.txt", UTF_8));
		x509 = IOUtils.resourceToString("/cf-forwarded-client-cert.txt", UTF_8);
	}

	@BeforeAll
	static void beforeAll() throws IOException {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withDomains("myauth.com")
				.withClientId("myClientId")
				.build();

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

		JwtValidatorBuilder
				.getInstance(configuration)
				.with(new JwtX5tValidator(configuration));
		cut = new IasTokenAuthenticator()
				.withServiceConfiguration(configuration)
				.withHttpClient(httpClientMock);
	}

	@Test
	void validateRequest_validTokenValidX5t_noCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenValidX5t.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertTrue(response.getUnauthenticatedReason().contains("Error during token validation: Client certificate missing"));
		assertFalse(response.isAuthenticated());

		when(httpRequest.getHeader(FWD_CLIENT_CERT_HEADER)).thenReturn("");
		TokenAuthenticationResult response2 = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertTrue(response2.getUnauthenticatedReason().contains("Error during token validation: Client certificate missing"));
		assertFalse(response2.isAuthenticated());
	}

	@Test
	void validateRequest_validTokenValidX5t_invalidCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenValidX5t.getTokenValue());
		when(httpRequest.getHeader(FWD_CLIENT_CERT_HEADER)).thenReturn("INVALIDx509");

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertTrue(response.getUnauthenticatedReason().contains("Error during token validation: Client certificate missing"));
		assertFalse(response.isAuthenticated());
	}

	@Test
	void validateRequest_validTokenInvalidX5t_withCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenInvalidX5t.getTokenValue());
		when(httpRequest.getHeader(FWD_CLIENT_CERT_HEADER)).thenReturn(x509);

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertTrue(response.getUnauthenticatedReason().contains("Error during token validation: Certificate thumbprint validation failed"));
		assertFalse(response.isAuthenticated());
	}

	@Test
	void validateRequest_validTokenWithCnf_withCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenValidX5t.getTokenValue());
		when(httpRequest.getHeader(FWD_CLIENT_CERT_HEADER)).thenReturn(x509);

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason(), emptyString());
		assertTrue(response.isAuthenticated());
	}

	private HttpServletRequest createRequestWithToken(String bearerAuthorizationHeader) {
		HttpServletRequest httpRequest = Mockito.mock(HttpServletRequest.class);
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + bearerAuthorizationHeader);
		return httpRequest;
	}
}
