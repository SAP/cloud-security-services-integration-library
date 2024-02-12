/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.Token;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static com.sap.cloud.security.config.Service.XSUAA;

class ReactiveSecurityContextTest {

	@Test
	void unauthenticated(){
		Authentication authentication = new TestingAuthenticationToken("Token", "theClientId", "ROLE_USER");
		Mono<Token> tokenMono = ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.map(Authentication::getCredentials)
				.flatMap(token -> ReactiveSecurityContext.getToken())
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

		StepVerifier.create(tokenMono)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	@Test
	void authenticated(){
		Token xsuaaToken = JwtGenerator.getInstance(XSUAA, "theClientId")
				.withAppId("xsapp")
				.withLocalScopes("ROLE_USER").createToken();
		Authentication authentication = new TestingAuthenticationToken(xsuaaToken, "theClientId", "ROLE_USER");
		Mono<Token> tokenMono = ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.map(Authentication::getCredentials)
				.flatMap(token -> ReactiveSecurityContext.getToken())
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

		StepVerifier.create(tokenMono)
				.expectNext(xsuaaToken)
				.verifyComplete();
	}
}
