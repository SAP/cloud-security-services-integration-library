package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class OAuth2SecurityFilterTest {

	public static final Token TOKEN = Mockito.mock(Token.class);
	private OAuth2SecurityFilter cut = null;
	private HttpServletResponse httpResponse;
	private HttpServletRequest httpRequest;
	private FilterChain filterChain;

	@Before
	public void setUp() {
		httpRequest = Mockito.mock(HttpServletRequest.class);
		httpResponse = Mockito.mock(HttpServletResponse.class);
		filterChain = Mockito.mock(FilterChain.class);
		cut = createComponent(ValidationResults.createValid());
	}

	@Test
	public void doFilter_noHeader_isUnauthorized() throws Exception {
		cut.doFilter(httpRequest, httpResponse, filterChain);

		assertThatResponseIsUnauthorized();
	}

	@Test
	public void doFilter_invalidToken_isUnauthorized() throws Exception {
		cut = createComponent((ValidationResults.createInvalid("Token is not valid")));
		cut.doFilter(httpRequest, httpResponse, filterChain);

		assertThatResponseIsUnauthorized();
	}

	@Test
	public void doFilter_validToken_containedInSecurityContext() throws Exception {
		mockAuthorizationHeader();

		cut = createComponent((ValidationResults.createValid()));
		cut.doFilter(httpRequest, httpResponse, filterChain);

		assertThat(SecurityContext.getToken()).isSameAs(TOKEN);
	}

	@Test
	public void doFilter_validToken_filterChainIsCalled() throws IOException, ServletException {
		mockAuthorizationHeader();

		cut = createComponent((ValidationResults.createValid()));
		cut.doFilter(httpRequest, httpResponse, filterChain);

		Mockito.verify(filterChain, times(1)).doFilter(httpRequest, httpResponse);
	}

	private void mockAuthorizationHeader() {
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer fake token");
	}

	private OAuth2SecurityFilter createComponent(ValidationResult validationResult) {
		return new OAuth2SecurityFilter((header) -> TOKEN, (TOKEN) -> validationResult);
	}

	private void assertThatResponseIsUnauthorized() {
		Mockito.verify(httpResponse, times(1)).setStatus(HttpStatus.SC_UNAUTHORIZED);
		Mockito.verifyNoMoreInteractions(httpResponse);
	}

}
