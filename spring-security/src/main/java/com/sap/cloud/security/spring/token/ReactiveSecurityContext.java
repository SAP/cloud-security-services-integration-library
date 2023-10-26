package com.sap.cloud.security.spring.token;

import com.sap.cloud.security.token.Token;
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
     * @return Mono object of type token or error of class
     *         {@link AccessDeniedException} in case there is no token, user is not
     *         authenticated.
     */
    public static Mono<Token> getToken() {
        return ReactiveSecurityContextHolder.getContext()
                .switchIfEmpty(Mono.error(new AccessDeniedException("Access forbidden: not authenticated")))
                .map(SecurityContext::getAuthentication)
                .map(Authentication::getPrincipal)
                .map(principal -> (Token) principal)
                .doOnSuccess(token -> logger.debug("Got Jwt token with clientid: {}", token.getClientId()))
                .doOnError(throwable -> logger.error("Access forbidden: SecurityContextHolder does not contain a principal of type 'Token'.", throwable));
    }
}
