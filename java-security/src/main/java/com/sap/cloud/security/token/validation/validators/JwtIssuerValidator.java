/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;
import static com.sap.cloud.security.token.validation.ValidationResults.createValid;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotEmpty;

/**
 * Validates that the jwt token is issued by a trust worthy identity provider.
 * <br>
 * It applies the following checks:
 * <ul>
 * <li>'iss' claim available</li>
 * <li>'iss' provides scheme</li>
 * <li>'iss' provides no query or fragment components or other problematic url
 * ingredients</li>
 * <li>'iss' or 'ias_iss' claim matches one of the domains of the trusted
 * identity provider</li>
 * </ul>
 * These checks are a prerequisite for using the `JwtSignatureValidator`.
 */
class JwtIssuerValidator implements Validator<Token> {
	private final List<String> domains;
	protected final Logger logger = LoggerFactory.getLogger(getClass());

	/**
	 * Creates instance of Issuer validation using the given domains provided by the
	 * identity service.
	 *
	 * @param domains
	 *            the list of domains of the identity provider
	 *            {@link OAuth2ServiceConfiguration#getDomains()}
	 */
	JwtIssuerValidator(List<String> domains) {
		assertNotEmpty(domains, "JwtIssuerValidator requires a domain(s).");
		this.domains = domains;
	}

	@Override
	public ValidationResult validate(Token token) {
		String issuer = token.getIssuer();
		if (token.getService().equals(Service.IAS) && !issuer.startsWith("http")) {
			issuer = "https://" + issuer;
		}
		ValidationResult validationResult = validateUrl(issuer);
		if (validationResult.isErroneous()) {
			return validationResult;
		}
		return matchesTokenIssuerUrl(issuer);
	}

	private ValidationResult matchesTokenIssuerUrl(String issuer) {
		URI issuerUri = URI.create(issuer);
		if (issuerUri.getQuery() == null && issuerUri.getFragment() == null && issuerUri.getHost() != null) {
			for (String d : domains) {
				if (issuerUri.getHost().endsWith(d)) {
					return createValid();
				}
			}
		}
		return createInvalid(
				"Issuer is not trusted because issuer '{}' doesn't match any of these domains '{}' of the identity provider.",
				issuer, domains);
	}

	private ValidationResult validateUrl(String issuer) {
		URI issuerUri;
		try {
			if (issuer == null || issuer.trim().isEmpty()) {
				return createInvalid(
						"Issuer validation can not be performed because Jwt token does not contain an issuer claim.");
			}
			if (!issuer.startsWith("http")) {
				return createInvalid(
						"Issuer is not trusted because issuer '{}' does not provide a valid URI (missing http scheme). Please contact your Identity Provider Administrator.",
						issuer);
			}
			issuerUri = new URI(issuer);
			if (issuerUri.getQuery() == null && issuerUri.getFragment() == null && issuerUri.getHost() != null) {
				return createValid();
			}
		} catch (URISyntaxException e) {
			logger.error(
					"Error: issuer claim '{}' does not provide a valid URI: {}. Please contact your Identity Provider Administrator.",
					issuer, e.getMessage(), e);
		}
		return createInvalid(
				"Issuer is not trusted because issuer does not provide a valid URI. Please contact your Identity Provider Administrator.",
				issuer);
	}

}
