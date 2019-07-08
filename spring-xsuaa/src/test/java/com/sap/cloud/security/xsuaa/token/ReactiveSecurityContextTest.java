package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

public class ReactiveSecurityContextTest {

	@Test
	public void unauthenticated() {
		SecurityContext expectedContext = new SecurityContextImpl();
		ReactiveSecurityContextHolder.withSecurityContext(Mono.just(expectedContext));
		Mono<XsuaaToken> tokenMono = ReactiveSecurityContext.getToken();

		StepVerifier.create(tokenMono)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	@Test
	@Ignore
	public void authenticated() {
		Jwt jwt = new XsuaaToken(new JwtGenerator().getToken());
		SecurityContext expectedContext = new SecurityContextImpl(
				new TestingAuthenticationToken("user", jwt, "ROLE_USER"));
		ReactiveSecurityContextHolder.withSecurityContext(Mono.just(expectedContext));
		Mono<XsuaaToken> tokenMono = ReactiveSecurityContext.getToken();

		StepVerifier.create(tokenMono).verifyComplete();
	}

}
