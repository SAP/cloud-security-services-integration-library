package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpringSecurityContextTest {
	AccessToken token;
	SapIdToken sapIdToken;
	private final ExecutorService executorService = Executors.newSingleThreadExecutor();

	@Before
	public void setUp() throws IOException {
		token = new XsuaaToken(IOUtils.resourceToString("/xsuaaUserAccessTokenRSA256.txt", UTF_8));
		sapIdToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
		SpringSecurityContext.clear();
	}

	@Test
	public void getToken_fromEmptySecurityContext_isNull() {
		Token token = SpringSecurityContext.getToken();
		assertThat(token).isNull();

		token = SpringSecurityContext.getAccessToken();
		assertThat(token).isNull();
	}

	@Test
	public void getToken() {
		setToken(sapIdToken);
		assertThat(SpringSecurityContext.getToken()).isEqualTo(sapIdToken);
	}

	@Test
	public void getAccessToken() {
		setToken(token);
		assertThat(SpringSecurityContext.getAccessToken()).isEqualTo(token);
	}

	@Test
	@Ignore // TODO IAS Support
	public void getAccessTokenReturnsNullIfTokenDoesNotImplementInterface() {
		setToken(sapIdToken);
		assertThat(SpringSecurityContext.getAccessToken()).isNull();
	}

	@Test
	public void clear_removesToken() {
		setToken(token);
		SpringSecurityContext.clear();

		assertThat(SpringSecurityContext.getToken()).isNull();
	}

	@Test
	public void tokenNotAvailableInDifferentThread() throws ExecutionException, InterruptedException {
		setToken(token);

		Future<Token> tokenInOtherThread = executorService.submit(() -> SpringSecurityContext.getToken());

		assertThat(tokenInOtherThread.get()).isNull();
	}

	@Test
	public void clearingTokenInDifferentThreadDoesNotAffectMainThread()
			throws ExecutionException, InterruptedException {
		setToken(token);

		executorService.submit(() -> SpringSecurityContext.clear()).get(); // run and await other thread

		assertThat(SpringSecurityContext.getToken()).isEqualTo(token);
	}

	private static void setToken(Token token) {
		SecurityContext context = new SecurityContextImpl();
		OAuth2Authentication authentication = SAPOfflineTokenServicesCloud.getOAuth2Authentication(token,
				"clientId", Collections.EMPTY_SET);

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE)).thenReturn(token.getTokenValue());

		authentication.setDetails(new OAuth2AuthenticationDetails(request));
		context.setAuthentication(authentication);
		SecurityContextHolder.clearContext();
		SecurityContextHolder.setContext(context);
		assertThat(SecurityContextHolder.getContext()).isEqualTo(context);
	}
}
