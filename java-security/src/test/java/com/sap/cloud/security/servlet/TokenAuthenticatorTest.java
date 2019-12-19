package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.sap.cloud.security.servlet.DefaultTokenAuthenticator.TokenExtractor;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

public class TokenAuthenticatorTest {

	private static final Token TOKEN = Mockito.mock(Token.class);
	private DefaultTokenAuthenticator cut = null;
	private HttpServletResponse httpResponse;
	private HttpServletRequest httpRequest;

	@Before
	public void setUp() {
		httpRequest = Mockito.mock(HttpServletRequest.class);
		httpResponse = Mockito.mock(HttpServletResponse.class);
		cut = createAuthenticator(ValidationResults.createValid());
		when(TOKEN.getService()).thenReturn(Service.XSUAA);
	}

	@Test
	public void defaultConstructor() {
		cut = new DefaultTokenAuthenticator();
	}

	@Test
	public void doFilter_noHeader_isUnauthenticated() {
		TokenAuthenticationResult response = cut.validateRequest(httpRequest, httpResponse);

		assertThat(response.isAuthenticated()).isFalse();
		assertThat(response.getUnauthenticatedReason()).contains("Authorization header is missing");
	}

	@Test
	public void doFilter_invalidToken_isUnauthenticated() {
		mockAuthorizationHeader();
		String errorMessage = "Token is not valid";
		cut = createAuthenticator((ValidationResults.createInvalid(errorMessage)));

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, httpResponse);

		assertThat(response.isAuthenticated()).isFalse();
		assertThat(response.getUnauthenticatedReason()).contains(errorMessage);
	}

	@Test
	public void doFilter_validToken_containedInSecurityContext() {
		mockAuthorizationHeader();

		cut = createAuthenticator((ValidationResults.createValid()));

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, httpResponse);

		assertThat(response.isAuthenticated()).isTrue();
		assertThat(response.getToken()).isSameAs(SecurityContext.getToken());
	}

	private void mockAuthorizationHeader() {
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer fake token");
	}

	private DefaultTokenAuthenticator createAuthenticator(ValidationResult validationResult) {
		TokenExtractor tokenExtractor = (header) -> TOKEN;
		Validator<Token> tokenValidator = (TOKEN) -> validationResult;

		return new DefaultTokenAuthenticator(tokenExtractor, tokenValidator);
	}

}
