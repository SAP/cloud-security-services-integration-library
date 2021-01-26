package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.token.InvalidTokenException;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.Assert;

/**
 * Internal class that decodes and validates the provided encoded token using
 * {@code java-security} client library.<br>
 * In case of successful validation, the token gets parsed and returned as
 * {@link Jwt}.
 */
public class HybridJwtDecoder implements JwtDecoder {
	CombiningValidator<Token> xsuaaTokenValidators;
	CombiningValidator<Token> iasTokenValidators;
	Logger logger = LoggerFactory.getLogger(getClass());

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
	public HybridJwtDecoder(CombiningValidator<Token> xsuaaValidator, CombiningValidator<Token> iasValidator) {
		xsuaaTokenValidators = xsuaaValidator;
		iasTokenValidators = iasValidator;
	}

	@Override
	public Jwt decode(String encodedToken) {
		Assert.hasText(encodedToken, "encodedToken must neither be null nor empty String.");
		Token token = Token.create(encodedToken);
		ValidationResult validationResult;

		switch (token.getService()) {
		case IAS:
			validationResult = iasTokenValidators.validate(token);
			break;
		case XSUAA:
			validationResult = xsuaaTokenValidators.validate(token);
			break;
		default:
			throw new InvalidTokenException("The token of service " + token.getService() + " is not supported.");
		}
		if (validationResult.isErroneous()) {
			throw new InvalidTokenException("The token is invalid: " + validationResult.getErrorDescription());
		}
		logger.debug("The token of service {} was successfully validated.", token.getService());
		return parseJwt(token);
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
