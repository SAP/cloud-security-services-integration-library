package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;
import static com.sap.cloud.security.token.validation.ValidationResults.createValid;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

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
 * Validates that the jwt token is issued by a trust worthy identity provider.
 * <br>
 * It applies the following checks:
 * <ul>
 * <li>'iss' claim available</li>
 * <li>'iss' claim matches url of trusted identity provider</li>
 * </ul>
 * These checks are a prerequisite for using the `JwtSignatureValidator`.
 */
class JwtIssuerValidator implements Validator<Token> {
	private final String domain;
	protected final Logger logger = LoggerFactory.getLogger(getClass());

	/**
	 * Creates instance of Issuer validation using the url.
	 *
	 * @param url
	 *            the url of the identity provider
	 *            {@link OAuth2ServiceConfiguration#getProperty(String)}
	 */
	JwtIssuerValidator(URI url) {
		assertNotNull(url, "JwtIssuerValidator requires a url.");
		this.domain = url.getHost();
	}

	/**
	 * Creates instance of Issuer validation using the domain.
	 *
	 * @param domain
	 *            the domain of the identity provider
	 *            {@link OAuth2ServiceConfiguration#getDomain()}
	 */
	JwtIssuerValidator(String domain) {
		assertNotNull(domain, "JwtIssuerValidator requires a domain or at least an url.");
		this.domain = domain;
	}

	@Override
	public ValidationResult validate(Token token) {
		String issuer = token.getClaimAsString(TokenClaims.ISSUER);
		if (issuer == null || issuer.trim().isEmpty()) {
			return createInvalid(
					"Issuer validation can not be performed because Jwt token does not contain 'iss' claim.");
		}
		return matchesTokenIssuerUrl(issuer);
	}

	private ValidationResult matchesTokenIssuerUrl(String issuer) {
		URI issuerUri;
		try {
			if (!issuer.startsWith("http")) {
				return createInvalid(
						"Issuer is not trusted because 'iss' claim '{}' does not provide a valid URI (missing http scheme). Please contact your Identity Provider Administrator.",
						issuer);
			}
			issuerUri = new URI(issuer);
			if (issuerUri.getQuery() == null && issuerUri.getFragment() == null
					&& issuerUri.getHost() != null && issuerUri.getHost().endsWith(domain)) {
				return createValid();
			}
		} catch (URISyntaxException e) {
			logger.error("Error: 'iss' claim '{}' does not provide a valid URI: {}.", issuer, e.getMessage(), e);
		}
		return createInvalid(
				"Issuer is not trusted because 'iss' '{}' does not match host '{}' of the identity provider.",
				issuer, domain);
	}

}
