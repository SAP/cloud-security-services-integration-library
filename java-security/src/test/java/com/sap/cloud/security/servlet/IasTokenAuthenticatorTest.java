package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@Ignore
public class IasTokenAuthenticatorTest {

	private final static HttpServletResponse HTTP_RESPONSE = Mockito.mock(HttpServletResponse.class);

	private final IasToken token;

	private AbstractTokenAuthenticator cut;

	public IasTokenAuthenticatorTest() throws IOException {
		/*
		TODO
		{
		  "aud": "T000169",
		  "sub": "P176945",
		  "mail": "xs2sec@kurzepost.de",
		  "iss": "https://xs2security.accounts400.ondemand.com",
		  "last_name": "xs2sec",
		  "exp": 6974031600,
		  "iat": 6974030600,
		  "first_name": "xs2sec",
		  "jti": "e21f7317-b4b9-42fd-b58b-3402d083ac77"
		}
		 */
		token = new IasToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
	}

	@Before
	public void setUp() throws IOException {
		OAuth2TokenKeyService tokenKeyService = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyService.retrieveTokenKeys(any())).thenReturn(
				JsonWebKeySetFactory.createFromJson(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8)));
		OAuth2ServiceConfiguration oAuth2ServiceConfiguration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withProperty(CFConstants.URL, "https://xs2security.accounts400.ondemand.com")
				.build();

		cut = new IasTokenAuthenticator()
				.withOAuth2TokenKeyService(
						OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyService))
				.withServiceConfiguration(oAuth2ServiceConfiguration);
	}

	@Test
	public void validateWhenConfigurationIsNull() {
		cut = new IasTokenAuthenticator();

		HttpServletRequest httpRequest = createRequestWithToken(token.getBearerAccessToken());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);
		assertThat(response.isAuthenticated()).isFalse();
		assertThat(response.getUnauthenticatedReason()).contains("Unexpected error occurred: There must be a service configuration.");
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
		HttpServletRequest httpRequest = createRequestWithToken(token.getBearerAccessToken());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason()).isEmpty();
		assertThat(response.isAuthenticated()).isTrue();
		assertThat(response.getToken()).isSameAs(SecurityContext.getToken());
	}

	@Test
	public void validateRequest_validToken_listenerIsCalled() {
		HttpServletRequest httpRequest = createRequestWithToken(token.getBearerAccessToken());
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
		HttpServletRequest httpRequest = createRequestWithToken("1" + token);
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

	private HttpServletRequest createRequestWithoutToken() {
		return Mockito.mock(HttpServletRequest.class);
	}

	private HttpServletRequest createRequestWithToken(String bearerAuthorizationHeader) {
		HttpServletRequest httpRequest = createRequestWithoutToken();
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(bearerAuthorizationHeader);
		return httpRequest;
	}

}
