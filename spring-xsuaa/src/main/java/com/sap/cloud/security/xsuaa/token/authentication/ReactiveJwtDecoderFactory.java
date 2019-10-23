package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import javax.annotation.Nonnull;

public interface ReactiveJwtDecoderFactory {

	/**
	 * Factory interface that is used by {@code XsuaaJwtDecoderBuilder} to create
	 * the actual reactive decoder instance.
	 *
	 * @param jku
	 *            the public key URL of the authorization server.
	 * @param tokenValidator
	 *            is used to validate the token. To combine several validators use
	 *            {@code DelegatingOAuth2TokenValidator}
	 * @return the {@code ReactiveJwtDecoder}.
	 */
	ReactiveJwtDecoder create(@Nonnull String jku, @Nonnull OAuth2TokenValidator<Jwt> tokenValidator);
}
