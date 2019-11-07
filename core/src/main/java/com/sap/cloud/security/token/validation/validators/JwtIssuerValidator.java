package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;
import static com.sap.cloud.security.token.validation.ValidationResults.createValid;

import java.net.URI;
import java.net.URISyntaxException;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;

public class JwtIssuerValidator implements Validator<Token> {
	private final String domain;

	/**
	 * @param domain the domain of the identity service {@link OAuth2ServiceConfiguration#getDomain()}
	 */
	public JwtIssuerValidator(String domain) {
		this.domain = domain;
	}

	@Override public ValidationResult validate(Token token) {

		String issuer = token.getClaimAsString(TokenClaims.ISSUER);
		if (issuer == null) {
			return createInvalid("Issuer validation can not be performed because JWT token does not contain 'iss' claim.");
		}

		URI issuerUri;
		try {
			issuerUri = new URI(issuer);
			if(!issuerUri.getHost().endsWith(domain)) {
				return createInvalid("Do not trust issuer because 'iss' '" + issuer + "' does not match domain '" + domain
						+ "' of the identity service.");
			}
		} catch (URISyntaxException e) {
			return createInvalid("Error: 'iss' claim'" + issuer + "' is not a valid URI.");
		}
		return createValid();
	}

}
