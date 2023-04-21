/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.Assert;

import javax.annotation.Nullable;

/**
 * Internal class that decodes and validates the provided encoded token using
 * {@code java-security} client library.<br>
 * In case of successful validation, the token gets parsed and returned as
 * {@link Jwt}.
 * <p>
 * Supports tokens issued by ias or xsuaa identity service.
 */
public class HybridJwtDecoder implements JwtDecoder {
	final CombiningValidator<Token> xsuaaTokenValidators;
	final CombiningValidator<Token> iasTokenValidators;
	private final Logger logger = LoggerFactory.getLogger(getClass());

	/**
	 * Creates instance with a set of validators for validating the access / oidc
	 * token issued by the dedicated identity service.
	 *
	 * @param xsuaaValidator
	 *            set of validators that should be used to validate a xsuaa access
	 *            token.
	 * @param iasValidator
	 *            set of validators that should be used to validate an ias oidc
	 *            token.
	 */
	public HybridJwtDecoder(CombiningValidator<Token> xsuaaValidator,
			@Nullable CombiningValidator<Token> iasValidator) {
		xsuaaTokenValidators = xsuaaValidator;
		iasTokenValidators = iasValidator;
	}

	@Override
	public Jwt decode(String encodedToken) {
		Token token;
		Jwt jwt;
		try {
			Assert.hasText(encodedToken, "encodedToken must neither be null nor empty String.");
			token = Token.create(encodedToken);
			jwt = parseJwt(token);
		} catch (RuntimeException ex) {
			throw new BadJwtException("Error initializing JWT decoder: " + ex.getMessage(), ex);
		}
		ValidationResult validationResult;
		switch (token.getService()) {
		case IAS -> {
			if (iasTokenValidators == null) {
				throw new BadJwtException("Tokens issued by IAS service aren't accepted");
			}
			validationResult = iasTokenValidators.validate(token);
		}
		case XSUAA -> validationResult = xsuaaTokenValidators.validate(token);
		default -> throw new BadJwtException("Tokens issued by " + token.getService() + " service aren't supported.");
		}
		if (validationResult.isErroneous()) {
			throw new BadJwtException("The token is invalid: " + validationResult.getErrorDescription());
		}
		logger.debug("Token issued by {} service was successfully validated.", token.getService());
		return jwt;
	}

	/**
	 * Parses decoded Jwt token to {@link Jwt}
	 *
	 * @param token
	 *            the token
	 * @return Jwt class
	 */
	public static Jwt parseJwt(Token token) {
		return new Jwt(token.getTokenValue(), token.getNotBefore(), token.getExpiration(),
				token.getHeaders(), token.getClaims());
	}

}
