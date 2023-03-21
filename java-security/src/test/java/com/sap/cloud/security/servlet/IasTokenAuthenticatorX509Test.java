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
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
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
		when(httpClientMock.execute(any(HttpGet.class)))
				.thenReturn(oidcResponse)
				.thenReturn(tokenKeysResponse);

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

		assertThat(response.getUnauthenticatedReason())
				.contains("Error during token validation: Client certificate missing");
		assertThat(response.isAuthenticated()).isFalse();

		when(httpRequest.getHeader(FWD_CLIENT_CERT_HEADER)).thenReturn("");
		TokenAuthenticationResult response2 = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response2.getUnauthenticatedReason())
				.contains("Error during token validation: Client certificate missing");
		assertThat(response2.isAuthenticated()).isFalse();

	}

	@Test
	void validateRequest_validTokenValidX5t_invalidCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenValidX5t.getTokenValue());
		when(httpRequest.getHeader(FWD_CLIENT_CERT_HEADER)).thenReturn("INVALIDx509");

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason())
				.contains("Error during token validation: Client certificate missing");
		assertThat(response.isAuthenticated()).isFalse();
	}

	@Test
	void validateRequest_validTokenInvalidX5t_withCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenInvalidX5t.getTokenValue());
		when(httpRequest.getHeader(FWD_CLIENT_CERT_HEADER)).thenReturn(x509);

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason())
				.contains("Error during token validation: Certificate thumbprint validation failed");
		assertThat(response.isAuthenticated()).isFalse();
	}

	@Test
	void validateRequest_validTokenWithCnf_withCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenValidX5t.getTokenValue());
		when(httpRequest.getHeader(FWD_CLIENT_CERT_HEADER)).thenReturn(x509);

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason()).isEmpty();
		assertThat(response.isAuthenticated()).isTrue();
	}

	private HttpServletRequest createRequestWithToken(String bearerAuthorizationHeader) {
		HttpServletRequest httpRequest = Mockito.mock(HttpServletRequest.class);
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + bearerAuthorizationHeader);
		return httpRequest;
	}
}
