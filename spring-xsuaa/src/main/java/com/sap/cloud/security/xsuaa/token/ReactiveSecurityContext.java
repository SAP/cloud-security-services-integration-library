package com.sap.cloud.security.xsuaa.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

public class ReactiveSecurityContext {
	private static Logger logger = LoggerFactory.getLogger(ReactiveSecurityContext.class);

	/**
	 * Obtain the Token object from the Spring Reactive SecurityContext
	 *
	 * @return Token object
	 * @throws AccessDeniedException
	 *             in case there is no token, user is not authenticated.
	 */
	static public Mono<Token> getToken() {
		return ReactiveSecurityContextHolder.getContext().flatMap(securityContext -> {
			if (securityContext == null) {
				throw new AccessDeniedException("Access forbidden: not authenticated");
			}
			Authentication authentication = securityContext.getAuthentication();
			if (authentication == null) {
				throw new AccessDeniedException("Access forbidden: not authenticated");
			}
			Jwt credentials = (Jwt) authentication.getCredentials();
			logger.info("Got the Jwt token: " + credentials.getTokenValue());

			return Mono.just(new XsuaaToken(credentials));
		});
	}
}
