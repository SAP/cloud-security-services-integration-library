package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import javax.annotation.Nonnull;

public interface JwtDecoderFactory {

	/**
	 * Factory interface that is used by {@code XsuaaJwtDecoderBuilder} to create
	 * the actual decoder instance.
	 *
	 * @param jku
	 *            the public key URL of the authorization server.
	 * @param tokenValidator
	 *            is used to validate the token. To combine several validators use
	 *            {@code DelegatingOAuth2TokenValidator}.
	 * @return the {@code JwtDecoder}.
	 */
	JwtDecoder create(@Nonnull String jku, @Nonnull OAuth2TokenValidator<Jwt> tokenValidator);
}
