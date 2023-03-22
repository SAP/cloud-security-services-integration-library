/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.mockito.Mockito;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.Mockito.when;

@Ignore
public class IasTokenAuthenticatorTest {

	private final static HttpServletResponse HTTP_RESPONSE = Mockito.mock(HttpServletResponse.class);

	private final SapIdToken token;

	private AbstractTokenAuthenticator cut;

	public IasTokenAuthenticatorTest() throws IOException {
		token = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
	}

//	@Before
//	public void setUp() throws IOException {
//		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
//				.forService(Service.IAS)
//				.withDomains("myauth.com")
//				.withClientId("T000310")
//				.build();
//
//		CloseableHttpClient httpClientMock = Mockito.mock(CloseableHttpClient.class);
//
//		CloseableHttpResponse oidcResponse = HttpClientTestFactory
//				.createHttpResponse("{\"jwks_uri\" : \"https://application.auth.com/oauth2/certs\"}");
//		CloseableHttpResponse tokenKeysResponse = HttpClientTestFactory
//				.createHttpResponse(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));
//		when(httpClientMock.execute(any(HttpGet.class)))
//				.thenReturn(oidcResponse)
//				.thenReturn(tokenKeysResponse);
//
//		cut = new IasTokenAuthenticator()
//				.withServiceConfiguration(configuration)
//				.withHttpClient(httpClientMock);
//	}
//
//	@Test
//	public void validateWhenConfigurationIsNull() {
//		cut = new IasTokenAuthenticator();
//
//		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue());
//
//		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);
//		assertThat(response.isAuthenticated()).isFalse();
//		assertThat(response.getUnauthenticatedReason())
//				.contains("Unexpected error occurred: There must be a service configuration.");
//	}
//
//	@Test
//	public void validateRequest_noHeader_isUnauthenticated() {
//		HttpServletRequest httpRequest = createRequestWithoutToken();
//
//		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);
//
//		assertThat(response.isAuthenticated()).isFalse();
//		assertThat(response.getUnauthenticatedReason()).contains("Authorization header is missing");
//	}
//
//	@Test
//	public void validateRequest_invalidToken_isUnauthenticated() {
//		String errorMessage = "JWT token does not consist of 'header'.'payload'.'signature'";
//		HttpServletRequest httpRequest = createRequestWithToken("Bearer invalid");
//
//		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);
//
//		assertThat(response.isAuthenticated()).isFalse();
//		assertThat(response.getUnauthenticatedReason()).contains(errorMessage);
//	}
//
//	@Test
//	public void validateRequest_validToken_containedInSecurityContext() {
//		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue());
//
//		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);
//
//		assertThat(response.getUnauthenticatedReason()).isEmpty();
//		assertThat(response.isAuthenticated()).isTrue();
//		assertThat(response.getToken()).isSameAs(SecurityContext.getToken());
//	}
//
//	@Test
//	public void validateRequest_validToken_listenerIsCalled() {
//		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue());
//		ValidationListener validationListener1 = Mockito.mock(ValidationListener.class);
//		ValidationListener validationListener2 = Mockito.mock(ValidationListener.class);
//
//		cut.withValidationListener(validationListener1)
//				.withValidationListener(validationListener2)
//				.validateRequest(httpRequest, HTTP_RESPONSE);
//
//		Mockito.verify(validationListener1, times(1)).onValidationSuccess();
//		Mockito.verify(validationListener2, times(1)).onValidationSuccess();
//		Mockito.verifyNoMoreInteractions(validationListener1);
//		Mockito.verifyNoMoreInteractions(validationListener2);
//	}
//
//	@Test
//	public void validateRequest_invalidToken_listenerIsCalled() {
//		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue() + "B");
//		ValidationListener validationListener1 = Mockito.mock(ValidationListener.class);
//		ValidationListener validationListener2 = Mockito.mock(ValidationListener.class);
//
//		cut.withValidationListener(validationListener1)
//				.withValidationListener(validationListener2)
//				.validateRequest(httpRequest, HTTP_RESPONSE);
//
//		Mockito.verify(validationListener1, times(1)).onValidationError(any());
//		Mockito.verify(validationListener2, times(1)).onValidationError(any());
//		Mockito.verifyNoMoreInteractions(validationListener2);
//		Mockito.verifyNoMoreInteractions(validationListener2);
//	}

	private HttpServletRequest createRequestWithoutToken() {
		return Mockito.mock(HttpServletRequest.class);
	}

	private HttpServletRequest createRequestWithToken(String bearerAuthorizationHeader) {
		HttpServletRequest httpRequest = createRequestWithoutToken();
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + bearerAuthorizationHeader);
		return httpRequest;
	}

}
