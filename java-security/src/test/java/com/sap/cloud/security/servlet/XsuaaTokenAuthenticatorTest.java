package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.Oauth2ServiceConfigurationTestFactory;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.XsuaaToken;
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
import static org.mockito.Mockito.when;

public class XsuaaTokenAuthenticatorTest {

	private final static HttpServletResponse HTTP_RESPONSE = Mockito.mock(HttpServletResponse.class);

	private final XsuaaToken xsuaaToken;
	private final OAuth2TokenKeyService tokenKeyService;
	private final OAuth2ServiceConfiguration oAuth2ServiceConfiguration;

	private AbstractTokenAuthenticator cut;

	public XsuaaTokenAuthenticatorTest() throws IOException {
		tokenKeyService = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyService.retrieveTokenKeys(any())).thenReturn(
				JsonWebKeySetFactory.createFromJson(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8)));
		oAuth2ServiceConfiguration = new OAuth2ServiceConfigurationBuilder()
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "auth.com")
				.withClientId("clientId").build();

		xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaUserAccessTokenRSA256.txt", UTF_8), "appId");
	}

	@Before
	public void setUp() {
		cut = new XsuaaTokenAuthenticator("appId")
				.withOAuth2TokenKeyService(
						OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyService))
				.withServiceConfiguration(oAuth2ServiceConfiguration);
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
		HttpServletRequest httpRequest = createRequestWithToken(xsuaaToken.getBearerAccessToken());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason()).isEmpty();
		assertThat(response.isAuthenticated()).isTrue();
		assertThat(response.getToken()).isSameAs(SecurityContext.getToken());
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
