/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

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
	protected static final String HTTPS_SCHEME = "https://";
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
		String issuer;

		try {
			issuer = token.getIssuer();
		} catch(JsonParsingException e) {
			return createInvalid("Issuer validation can not be performed because token issuer claim was not a String value.");
		}

		if (issuer == null || issuer.trim().isEmpty()) {
			return createInvalid("Issuer validation can not be performed because token does not contain an issuer claim.");
		}

		String issuerUrl = issuer.startsWith(HTTPS_SCHEME) || issuer.startsWith("http://localhost") ? issuer : HTTPS_SCHEME + issuer;

		try {
			new URL(issuerUrl);
		} catch (MalformedURLException e) {
			return createInvalid("Issuer validation can not be performed because token issuer is not a valid URL suitable for https.");
		}

		String issuerDomain = issuerUrl.substring(issuerUrl.indexOf("://") + 3); // issuerUrl was validated above to begin either with http:// or https://
		for(String d : domains) {
			// a string that ends with .<trustedDomain> and contains 1-63 letters, digits or '-' before that for the subdomain
			String validSubdomainPattern = String.format("^[a-zA-Z0-9-]{1,63}\\.%s$", Pattern.quote(d));
			if(Objects.equals(d, issuerDomain) || issuerDomain.matches(validSubdomainPattern)) {
				return createValid();
			}
		}

		return createInvalid("Issuer {} was not a trusted domain or a subdomain of the trusted domains {}.", issuer, domains);
	}
}
