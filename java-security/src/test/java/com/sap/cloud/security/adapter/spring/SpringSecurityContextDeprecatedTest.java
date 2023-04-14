/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.token.*;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpringSecurityContextDeprecatedTest {
	AccessToken token;
	SapIdToken sapIdToken;
	private final ExecutorService executorService = Executors.newSingleThreadExecutor();
	private static final Set<String> NO_SCOPES = Collections.EMPTY_SET;

	@BeforeEach
	public void setUp() throws IOException {
		token = new XsuaaToken(IOUtils.resourceToString("/xsuaaUserAccessTokenRSA256.txt", UTF_8));
		sapIdToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
		SpringSecurityContext.clear();
	}

	@Test
	public void getToken() {
		setToken(sapIdToken, NO_SCOPES);
		assertThat(SpringSecurityContext.getToken()).isEqualTo(sapIdToken);

		setToken(token, NO_SCOPES);
		assertThat(SpringSecurityContext.getToken()).isEqualTo(token);
	}

	@Test
	public void getAccessToken() {
		setToken(token, NO_SCOPES);
		assertThat(SpringSecurityContext.getAccessToken()).isEqualTo(token);
	}

	@Test
	public void getAccessTokenScopes() {
		Set<String> scopes = new HashSet<>();
		scopes.add("Scope1");
		scopes.add("Scope2");

		setToken(token, scopes);
		assertThat(SpringSecurityContext.getAccessToken().getScopes()).isEmpty();
		assertThat(SpringSecurityContext.getAccessToken().hasLocalScope("Scope1")).isTrue();
		assertThat(SpringSecurityContext.getAccessToken().hasLocalScope("Scope3")).isFalse();
	}

	@Test
	public void clear_removesToken() {
		setToken(token, NO_SCOPES);
		SpringSecurityContext.clear();

		assertThat(SpringSecurityContext.getToken()).isNull();
	}

	@Test
	public void tokenNotAvailableInDifferentThread() throws ExecutionException, InterruptedException {
		setToken(token, NO_SCOPES);

		Future<Token> tokenInOtherThread = executorService.submit(() -> SpringSecurityContext.getToken());

		assertThat(tokenInOtherThread.get()).isNull();
	}

	@Test
	public void clearingTokenInDifferentThreadDoesNotAffectMainThread()
			throws ExecutionException, InterruptedException {
		setToken(token, NO_SCOPES);

		executorService.submit(() -> SpringSecurityContext.clear()).get(); // run and await other thread

		assertThat(SpringSecurityContext.getToken()).isEqualTo(token);
	}

	private static void setToken(Token token, Set<String> scopes) {
		SecurityContext context = new SecurityContextImpl();
		OAuth2Authentication authentication = SAPOfflineTokenServicesCloud.createOAuth2Authentication(
				"clientId", scopes, token);

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE)).thenReturn(token.getTokenValue());
		authentication.setDetails(new OAuth2AuthenticationDetails(request));

		context.setAuthentication(authentication);
		SecurityContextHolder.clearContext();
		SecurityContextHolder.setContext(context);
		assertThat(SecurityContextHolder.getContext()).isEqualTo(context);
	}
}
