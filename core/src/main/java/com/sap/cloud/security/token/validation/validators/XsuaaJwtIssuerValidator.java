package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.validation.ValidationResults.*;

import java.net.URI;
import java.net.URISyntaxException;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;

public class XsuaaJwtIssuerValidator implements Validator<Token> {
	private final String domain;

	/**
	 *
	 * @param uaaDomain the domain of the identity service {@link OAuth2ServiceConfiguration#getDomain()}
	 */
	public XsuaaJwtIssuerValidator(String uaaDomain) {
		this.domain = uaaDomain;
	}

	@Override public ValidationResult validate(Token token) {

		String tokenKeyUrl = token.getHeaderParameterAsString(TokenHeader.JWKS_URL);
		if (tokenKeyUrl == null) {
			return createInvalid("Issuer validation can not be performed because JWT token does not contain 'jku' header parameter.");
		}

		URI jkuUri;
		try {
			jkuUri = new URI(tokenKeyUrl);
			if(!jkuUri.getHost().endsWith(domain)) {
				return createInvalid("Issuer is not trusted because 'jku' '{}' does not match uaa domain '{}'.",
						tokenKeyUrl, domain);
			}
		} catch (URISyntaxException e) {
			return createInvalid("Error: 'jku' header parameter '{}' does not provide a valid URI.", tokenKeyUrl);
		}
		return createValid();
	}

}
