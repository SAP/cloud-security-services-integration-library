/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.TokenClaims.IAS_ISSUER;
import static com.sap.cloud.security.token.TokenClaims.ISSUER;
import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;
import static com.sap.cloud.security.token.validation.ValidationResults.createValid;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotEmpty;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
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
	private final List<String> domains;
	protected final Logger logger = LoggerFactory.getLogger(getClass());

	/**
	 * Creates instance of Issuer validation using the domain.
	 *
	 * @param domains
	 *            the list of domains of the identity provider
	 *            {@link OAuth2ServiceConfiguration#getDomains()}
	 */
	JwtIssuerValidator(List<String> domains) {
		assertNotEmpty(domains, "JwtIssuerValidator requires a domain(s).");
		this.domains = domains;
	}

	/**
	 * Extracts the domain from a url without the subdomain. If no subdomain exists,
	 * just returns the host.
	 *
	 * @param {string}
	 *            fullUrl - Example: https://sub.domain.com
	 * @returns {string} - host without subdomain - Example: domain.com
	 */
	/*
	 * private static String getSubdomain(URI uri) { String host = uri.getHost();
	 * return host.replaceFirst(host.split("\\.")[0] + ".", ""); }
	 */
	@Override
	public ValidationResult validate(Token token) {
		ValidationResult validationResult;
		String ias_issuer_url = token.getClaimAsString(IAS_ISSUER);
		String issuer_url = token.getClaimAsString(ISSUER);

		validationResult = validateUrl(issuer_url, ISSUER);
		if (validationResult.isErroneous()) {
			return validationResult;
		}
		if (hasValue(ias_issuer_url)) {
			validationResult = validateUrl(ias_issuer_url, IAS_ISSUER);
			if (validationResult.isErroneous()) {
				return validationResult;
			}
			return matchesTokenIssuerUrl(ias_issuer_url, IAS_ISSUER);
		}
		return matchesTokenIssuerUrl(issuer_url, ISSUER);
	}

	private ValidationResult matchesTokenIssuerUrl(String issuer, String claimName) {
		URI issuerUri = URI.create(issuer);
		if (issuerUri.getQuery() == null && issuerUri.getFragment() == null && issuerUri.getHost() != null) {
			for (String d : domains) {
				if (issuerUri.getHost().endsWith(d)) {
					return createValid();
				}
			}
		}
		return createInvalid(
				"Issuer is not trusted because '{}' '{}' doesn't match any of these domains '{}' of the identity provider.",
				claimName, issuer, domains);
	}

	private ValidationResult validateUrl(String issuer, String claimName) {
		URI issuerUri;
		try {
			if (issuer == null || issuer.trim().isEmpty()) {
				return createInvalid(
						"Issuer validation can not be performed because Jwt token does not contain '{}' claim.",
						claimName);
			}
			if (!issuer.startsWith("http")) {
				return createInvalid(
						"Issuer is not trusted because '{}' claim '{}' does not provide a valid URI (missing http scheme). Please contact your Identity Provider Administrator.",
						claimName, issuer);
			}
			issuerUri = new URI(issuer);
			if (issuerUri.getQuery() == null && issuerUri.getFragment() == null && issuerUri.getHost() != null) {
				return createValid();
			}
		} catch (URISyntaxException e) {
			logger.error(
					"Error: '{}' claim '{}' does not provide a valid URI: {}. Please contact your Identity Provider Administrator.",
					claimName, issuer, e.getMessage(), e);
		}
		return createInvalid(
				"Issuer is not trusted because '{}' claim '{}' does not provide a valid URI. Please contact your Identity Provider Administrator.",
				claimName, issuer);
	}

	private static boolean hasValue(String issuer) {
		return issuer != null && !issuer.trim().isEmpty();
	}

}
