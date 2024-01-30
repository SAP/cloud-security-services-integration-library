/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;

public class ReactiveSecurityContextTest {


	Token xsuaaToken;

	public Token generateXsuaaToken(){
		return JwtGenerator.getInstance(XSUAA, "theClientId")
				.withAppId("xsapp")
				.withLocalScopes("ROLE_USER").createToken();
	}
	@Test
	public void unauthenticated(){
		SecurityContextImpl expectedContext = new SecurityContextImpl();
		ReactiveSecurityContextHolder.withSecurityContext(Mono.just(expectedContext));
		Mono<Token> tokenMono = ReactiveSecurityContext.getToken();

		StepVerifier.create(tokenMono)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	@Test
	@Ignore
	public void authenticated(){
		xsuaaToken = generateXsuaaToken();
		SecurityContextImpl expectedContext = new SecurityContextImpl(
				new TestingAuthenticationToken("theClientId", xsuaaToken, "ROLE_USER"));
		ReactiveSecurityContextHolder.withSecurityContext(Mono.just(expectedContext));
		Mono<Token> tokenMono = ReactiveSecurityContext.getToken();

		StepVerifier.create(tokenMono)
				.expectNext(xsuaaToken)
				.verifyComplete();
	}

	/*
	@Test
	public void unauthenticated() {
		SecurityContext expectedContext = new SecurityContextImpl();
		ReactiveSecurityContextHolder.withSecurityContext(Mono.just(expectedContext));
		Mono<Token> tokenMono = ReactiveSecurityContext.getToken();

		StepVerifier.create(tokenMono)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	@Test
	@Ignore
	public void authenticated() {
		Token jwt = new Token(new JwtGenerator().setUserName("user").getToken());
		SecurityContext expectedContext = new SecurityContextImpl(
				new TestingAuthenticationToken("user", jwt, "ROLE_USER"));
		ReactiveSecurityContextHolder.withSecurityContext(Mono.just(expectedContext));
		Mono<XsuaaToken> tokenMono = ReactiveSecurityContext.getToken();

		StepVerifier.create(tokenMono)
				.expectNext(jwt)
				.verifyComplete();
	}

	 */

}
