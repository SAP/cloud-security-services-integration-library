/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.x509.X509Certificate;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;

/**
 * Internal class that decodes and validates the provided encoded token using {@code java-security} client library.<br>
 * In case of successful validation, the token gets parsed and returned as {@link Jwt}.
 * <p>
 * Supports only id tokens issued by ias identity service.
 */
public class IasJwtDecoder implements JwtDecoder {
	final CombiningValidator<Token> tokenValidators;
	private final Logger logger = LoggerFactory.getLogger(getClass());

	/**
	 * Creates instance with a set of validators for validating the oidc token issued by the ias identity service.
	 *
	 * @param validator
	 * 		set of validators that should be used to validate an ias oidc token.
	 */
	public IasJwtDecoder(CombiningValidator<Token> validator) {
		tokenValidators = validator;
	}

	@Override
	public Jwt decode(String encodedToken) {
		try {
			ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

			if (servletRequestAttributes != null) {
				HttpServletRequest request = servletRequestAttributes.getRequest();
				String clientCert = request.getHeader(FWD_CLIENT_CERT_HEADER);
				if (clientCert != null) {
					SecurityContext.setClientCertificate(X509Certificate.newCertificate(clientCert));
				}
			}
			Assert.hasText(encodedToken, "encodedToken must neither be null nor empty String.");
			Token token = Token.create(encodedToken);
			ValidationResult validationResult = tokenValidators.validate(token);
			if (validationResult.isRetryable()) {
				throw new JwtException(validationResult.getErrorDescription());
			}
			if (validationResult.isErroneous()) {
				throw new InvalidBearerTokenException("The token is invalid.");
			}
			logger.debug("The token of service {} was successfully validated.", token.getService());
			return parseJwt(token);
		} catch (RuntimeException ex) {
			throw new BadJwtException("Error initializing JWT decoder: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Parses decoded Jwt token to {@link Jwt}
	 *
	 * @param token
	 * 		the token
	 * @return Jwt class
	 */
	public static Jwt parseJwt(Token token) {
		return new Jwt(token.getTokenValue(), token.getNotBefore(), token.getExpiration(),
				token.getHeaders(), token.getClaims());
	}

}
