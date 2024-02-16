/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

public class ReactiveSecurityContext {
	private static final Logger logger = LoggerFactory.getLogger(ReactiveSecurityContext.class);

	private ReactiveSecurityContext() {
	}

	/**
	 * Obtain the Token object from the Spring Reactive SecurityContext
	 *
	 * @return Mono object of type token or error of class {@link AccessDeniedException} in case there is no token, user
	 * 		is not authenticated.
	 */
	public static Mono<XsuaaToken> getToken() {
		return ReactiveSecurityContextHolder.getContext()
				.switchIfEmpty(Mono.error(new AccessDeniedException("Access forbidden: not authenticated")))
				.map(SecurityContext::getAuthentication)
				.map(Authentication::getCredentials)
				.map(credentials -> new XsuaaToken((Jwt) credentials))
				.doOnSuccess(token -> logger.debug("Got Jwt token with clientid: {}", token.getClientId()))
				.doOnError(throwable -> logger.error("ERROR to getToken", throwable));
	}
}
