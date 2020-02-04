package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;
import static com.sap.cloud.security.token.validation.ValidationResults.createValid;
import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;

import java.net.URI;
import java.net.URISyntaxException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;

/**
 * Validates that the jwt access token is issued by a trust worthy identity
 * service.
 */
public class JwtIssuerValidator implements Validator<Token> {
	private final String domain;
	protected final Logger logger = LoggerFactory.getLogger(getClass());

	/**
	 * @param domain
	 *            the domain of the identity service
	 *            {@link OAuth2ServiceConfiguration#getProperty(String)}
	 */
	public JwtIssuerValidator(String domain) {
		assertHasText(domain, "domain must not be null or empty.");
		this.domain = domain;
	}

	@Override
	public ValidationResult validate(Token token) {
		String issuer = token.getClaimAsString(TokenClaims.ISSUER);
		if (issuer == null || issuer.trim().isEmpty()) {
			return createInvalid(
					"Issuer validation can not be performed because Jwt token does not contain 'iss' claim.");
		}

		return matchesTokenIssuerDomain(issuer);
	}

	private ValidationResult matchesTokenIssuerDomain(String issuer) {
		URI issuerUri;
		try {
			issuerUri = issuer.startsWith("http") ? new URI(issuer) : new URI("https://" + issuer);
			if (issuerUri.getHost() != null && issuerUri.getHost().endsWith(domain)) {
				return createValid();
			}
		} catch (URISyntaxException e) {
			logger.error("Error: 'iss' claim '{}' does not provide a valid URI: {}.", issuer, e.getMessage(), e);
		}
		return createInvalid(
				"Issuer is not trusted because 'iss' '{}' does not match domain '{}' of the identity service.",
				issuer, domain);
	}

}
