/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.token.*;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoder;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.token.TokenClaims.SUBJECT;
import static com.sap.cloud.security.xsuaa.token.SpringSecurityContext.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singleton;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpringSecurityContextTest {
	private final ExecutorService executorService = Executors.newSingleThreadExecutor();
	AccessToken token;
	SapIdToken sapIdToken;

	@BeforeEach
	public void setUp() throws IOException {
		token = new XsuaaToken(IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8));
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
	public void getTokenReturnsAnyToken() {
		// initialize SpringSecurityContext with provided token
		setToken(sapIdToken);
		assertThat(SpringSecurityContext.getToken()).isEqualTo(sapIdToken);

		setToken(token);
		assertThat(SpringSecurityContext.getToken()).isEqualTo(token);
	}

	@Test
	public void getAccessTokenReturnsXsuaaToken() {
		setToken(token);
		assertThat(SpringSecurityContext.getAccessToken()).isEqualTo(token);
	}

	@Test
	public void getTokenReturnsIasOidcToken() {
		setToken(sapIdToken);
		assertThat(SpringSecurityContext.getToken().getService()).isEqualTo(IAS);
		assertThat(SpringSecurityContext.getToken().getClaimAsString(SUBJECT)).isEqualTo("P176945");
	}

	@Test
	public void getAccessTokenWithAlternativeSetterReturnsIasOidcToken() {
		setTokenViaMockedAuthentication(sapIdToken);
		assertThat(SpringSecurityContext.getToken()).isEqualTo(sapIdToken);
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

		executorService.submit(SpringSecurityContext::clear).get(); // run and await other thread

		assertThat(SpringSecurityContext.getToken()).isEqualTo(token);
	}

	private static void setToken(Token token) {
		XsuaaJwtDecoder mockXsuaaJwtDecoder = Mockito.mock(XsuaaJwtDecoder.class);
		when(mockXsuaaJwtDecoder.decode(token.getTokenValue()))
				.thenReturn(convertTokenToOAuthJwt(token.getTokenValue()));

		// initialize SpringSecurityContext with provided token
		init(token.getTokenValue(), mockXsuaaJwtDecoder, new DefaultAuthoritiesExtractor());
	}

	@Nullable
	public static Jwt convertTokenToOAuthJwt(String token) {
		return parseJwt(decodeJwt(token));
	}

	private static Jwt parseJwt(DecodedJwt decodedJwt) {
		JSONObject payload = new JSONObject(decodedJwt.getPayload());
		JSONObject header = new JSONObject(decodedJwt.getHeader());
		return new Jwt(decodedJwt.getEncodedToken(), Instant.ofEpochSecond(payload.optLong("iat")),
				Instant.ofEpochSecond(payload.getLong("exp")),
				header.toMap(), payload.toMap());
	}

	static DecodedJwt decodeJwt(String encodedJwtToken) {
		return Base64JwtDecoder.getInstance().decode(encodedJwtToken);
	}

	private static void setTokenViaMockedAuthentication(Token token) {
		OidcIdToken oidcIdToken = new OidcIdToken(token.getTokenValue(), Instant.now(), Instant.now().plusSeconds(1L),
				token.getClaims());
		SecurityContextHolder.getContext().setAuthentication(getMockAuthentication(oidcIdToken));
	}

	static Authentication getMockAuthentication(OidcIdToken oidcIdToken) {
		Authentication authentication = mock(Authentication.class);
		when(authentication.getPrincipal())
				.thenReturn(new DefaultOidcUser(singleton(new SimpleGrantedAuthority("openid")), oidcIdToken));
		when(authentication.isAuthenticated()).thenReturn(true);
		return authentication;
	}
}
