/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.spring.token.authentication.HybridJwtDecoder;
import com.sap.cloud.security.spring.token.authentication.XsuaaTokenAuthorizationConverter;
import com.sap.cloud.security.token.Token;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class SpringSecurityContextTest {
	Token xsuaaToken;
	Token sapIdToken;
	private final ExecutorService executorService = Executors.newSingleThreadExecutor();

	@BeforeEach
	void setUp() {
		xsuaaToken = JwtGenerator.getInstance(XSUAA, "theClientId")
				.withAppId("xsapp")
				.withLocalScopes("Scope1").createToken();
		sapIdToken = JwtGenerator.getInstance(IAS, "theClientId").createToken();
		SpringSecurityContext.clear();
	}

	@Test
	void getSecurityContextRaiseAccessDeniedExceptionIfNotInitialized() {
		assertThrows(AccessDeniedException.class, SpringSecurityContext::getToken);
	}

	@Test
	void initSecurityContextRaiseExceptionIfNotHybridJwtDecoder() {
		String tokenValue = xsuaaToken.getTokenValue();
		JwtDecoder jwtDecoder = new JwtDecoder() {
			@Override
			public Jwt decode(String s) throws JwtException {
				return HybridJwtDecoder.parseJwt(xsuaaToken);
			}
		};
		assertThrows(IllegalArgumentException.class, () -> {
			SpringSecurityContext.init(tokenValue, jwtDecoder, Mockito.mock(XsuaaTokenAuthorizationConverter.class));
		});
	}

	@Test
	void initSecurityContextRaiseExceptionIfConverterIsNull() {
		String tokenValue = xsuaaToken.getTokenValue();
		assertThrows(IllegalArgumentException.class, () -> {
			SpringSecurityContext.init(tokenValue, Mockito.mock(HybridJwtDecoder.class), null);
		});
	}

	@Test
	void getToken_fromEmptySecurityContext_isNull() {
		assertThrows(AccessDeniedException.class, SpringSecurityContext::getAccessToken);
		assertThrows(AccessDeniedException.class, SpringSecurityContext::getToken);
	}

	@Test
	void getToken() {
		setToken(sapIdToken);
		assertEquals(sapIdToken, SpringSecurityContext.getToken());

		setToken(xsuaaToken);
		assertEquals(xsuaaToken, SpringSecurityContext.getToken());
	}

	@Test
	void getToken_fromJavaSpringSecurityContext() {
		setToken(sapIdToken);
		assertEquals(sapIdToken, com.sap.cloud.security.adapter.spring.SpringSecurityContext.getToken());

		setToken(xsuaaToken);
		assertEquals(xsuaaToken, com.sap.cloud.security.adapter.spring.SpringSecurityContext.getToken());
	}

	@Test
	void getAccessToken() {
		setToken(xsuaaToken);
		assertEquals(xsuaaToken, SpringSecurityContext.getAccessToken());
	}

	@Test
	void getAccessTokenScopes() {
		setToken(xsuaaToken);
		assertFalse(SpringSecurityContext.getAccessToken().hasScope("xsapp.Scope3"));
		assertTrue(SpringSecurityContext.getAccessToken().hasScope("xsapp.Scope1"));
	}

	@Test
	void getAccessTokenReturnsNull_inCaseOfIasToken() {
		setToken(sapIdToken);
		assertNull(SpringSecurityContext.getAccessToken()); // shall throw exception?
	}

	@Test
	void getTokenReturnsIasOidcToken() {
		setToken(sapIdToken);
		assertEquals(IAS, SpringSecurityContext.getToken().getService());
		assertEquals("theClientId", SpringSecurityContext.getToken().getClientId());
	}

	@Test
	void clear_removesToken() {
		setToken(xsuaaToken);
		SpringSecurityContext.clear();
		com.sap.cloud.security.adapter.spring.SpringSecurityContext.clear();

		assertThrows(AccessDeniedException.class, () -> SpringSecurityContext.getToken());
		assertThrows(AccessDeniedException.class, () -> SpringSecurityContext.getAccessToken());

		assertNull(com.sap.cloud.security.adapter.spring.SpringSecurityContext.getToken());
		assertNull(com.sap.cloud.security.adapter.spring.SpringSecurityContext.getAccessToken());
	}

	@Test
	void clear_removesTokenFromJavaSpringSecurityContext() {
		com.sap.cloud.security.adapter.spring.SpringSecurityContext.clear();

		assertNull(com.sap.cloud.security.adapter.spring.SpringSecurityContext.getToken());
		assertNull(com.sap.cloud.security.adapter.spring.SpringSecurityContext.getAccessToken());
	}

	// @Test
	void tokenNotAvailableInDifferentThread() {
		setToken(xsuaaToken);

		Future<Token> tokenInOtherThread = executorService.submit(() -> SpringSecurityContext.getToken());

		assertThrows(AccessDeniedException.class, () -> tokenInOtherThread.get());
	}

	@Test
	void clearingTokenInDifferentThreadDoesNotAffectMainThread()
			throws ExecutionException, InterruptedException {
		setToken(xsuaaToken);

		executorService.submit(() -> SpringSecurityContext.clear()).get(); // run and await other thread
		assertEquals(xsuaaToken, SpringSecurityContext.getToken());
	}

	private static void setToken(Token token) {
		HybridJwtDecoder mockJwtDecoder = Mockito.mock(HybridJwtDecoder.class);
		when(mockJwtDecoder.decode(token.getTokenValue())).thenReturn(HybridJwtDecoder.parseJwt(token));

		// initialize SpringSecurityContext with provided token
		SpringSecurityContext.init(token.getTokenValue(), mockJwtDecoder,
				new XsuaaTokenAuthorizationConverter("xsapp"));
	}
}
