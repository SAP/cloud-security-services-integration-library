package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.validation.ValidationResults.*;

import java.net.URI;
import java.net.URISyntaxException;

import com.sap.cloud.security.core.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;

public class XsuaaJwtIssuerValidator implements Validator<Token> {
	private final String uaaDomain;

	/**
	 *
	 * @param uaaDomain the domain of the identity service {@link OAuth2ServiceConfiguration#getDomain()}
	 */
	public XsuaaJwtIssuerValidator(String uaaDomain) {
		this.uaaDomain = uaaDomain;
	}

	@Override public ValidationResult validate(Token token) {

		String tokenKeyUrl = token.getHeaderParameterAsString(TokenHeader.JWKS_URL);
		if (tokenKeyUrl == null) {
			return createInvalid("Issue Validation can not be performed because JWT token does not contain 'jku' header parameter.");
		}

		URI jkuUri;
		try {
			jkuUri = new URI(tokenKeyUrl);
			if(!jkuUri.getHost().endsWith(uaaDomain)) {
				return createInvalid("Error: Do not trust issuer because 'jku' '" + tokenKeyUrl + "' does not match uaa domain '" + uaaDomain + "'.");
			}
		} catch (URISyntaxException e) {
			return createInvalid("Error: 'jku' header parameter '" + tokenKeyUrl + "' is not a valid URI.");
		}
		return createValid();
	}

}
