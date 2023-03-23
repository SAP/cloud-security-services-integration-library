/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoder;
import edu.umd.cs.findbugs.annotations.Nullable;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import static com.sap.cloud.security.xsuaa.token.SpringSecurityContext.init;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singleton;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SpringSecurityContextTest {
	private final ExecutorService executorService = Executors.newSingleThreadExecutor();
	AccessToken token;
	SapIdToken sapIdToken;

	@BeforeEach
	void setUp() throws IOException {
		token = new XsuaaToken(IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8));
		sapIdToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
		SpringSecurityContext.clear();
	}

	@Test
	void getToken_fromEmptySecurityContext_isNull() {
		Token token = SpringSecurityContext.getToken();
		assertNull(token);

		token = SpringSecurityContext.getAccessToken();
		assertNull(token);
	}

	@Test
	void getTokenReturnsAnyToken() {
		// initialize SpringSecurityContext with provided token
		setToken(sapIdToken);
		assertEquals(sapIdToken, SpringSecurityContext.getToken());

		setToken(token);
		assertEquals(token, SpringSecurityContext.getToken());
	}

	@Test
	void getAccessTokenReturnsXsuaaToken() {
		setToken(token);
		assertEquals(token, SpringSecurityContext.getAccessToken());
	}

	@Test
	void getTokenReturnsIasOidcToken() {
		setToken(sapIdToken);
		assertEquals(IAS, SpringSecurityContext.getToken().getService());
		assertEquals("P176945", SpringSecurityContext.getToken().getClaimAsString(SUBJECT));
	}

	@Test
	void getAccessTokenWithAlternativeSetterReturnsIasOidcToken() {
		setTokenViaMockedAuthentication(sapIdToken);
		assertEquals(sapIdToken, SpringSecurityContext.getToken());
	}

	@Test
	void clear_removesToken() {
		setToken(token);
		SpringSecurityContext.clear();

		assertNull(SpringSecurityContext.getToken());
	}

	@Test
	void tokenNotAvailableInDifferentThread() throws ExecutionException, InterruptedException {
		setToken(token);

		Future<Token> tokenInOtherThread = executorService.submit(SpringSecurityContext::getToken);

		assertNull(tokenInOtherThread.get());
	}

	@Test
	void clearingTokenInDifferentThreadDoesNotAffectMainThread()
			throws ExecutionException, InterruptedException {
		setToken(token);

		executorService.submit(SpringSecurityContext::clear).get(); // run and await other thread

		assertEquals(token, SpringSecurityContext.getToken());
	}

	private static void setToken(Token token) {
		XsuaaJwtDecoder mockXsuaaJwtDecoder = mock(XsuaaJwtDecoder.class);
		when(mockXsuaaJwtDecoder.decode(token.getTokenValue()))
				.thenReturn(convertTokenToOAuthJwt(token.getTokenValue()));

		// initialize SpringSecurityContext with provided token
		init(token.getTokenValue(), mockXsuaaJwtDecoder, new DefaultAuthoritiesExtractor());
	}

	@Nullable
	static Jwt convertTokenToOAuthJwt(String token) {
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
