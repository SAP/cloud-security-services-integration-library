package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.core.Assertions.assertNotEmpty;
import static com.sap.cloud.security.token.validation.ValidationResults.*;

import java.net.URI;
import java.net.URISyntaxException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;

public class XsuaaJwtIssuerValidator implements Validator<Token> {
	private final String domain;
	protected final Logger logger = LoggerFactory.getLogger(getClass());

	/**
	 *
	 * @param uaaDomain the domain of the identity service {@link OAuth2ServiceConfiguration#getDomain()}
	 */
	public XsuaaJwtIssuerValidator(String uaaDomain) {
		assertNotEmpty(uaaDomain, "uaaDomain must not be null or empty.");
		this.domain = uaaDomain;
	}

	@Override public ValidationResult validate(Token token) {
		String tokenKeyUrl = token.getHeaderParameterAsString(TokenHeader.JWKS_URL);
		if (tokenKeyUrl == null || tokenKeyUrl.trim().isEmpty()) {
			return createInvalid("Issuer validation can not be performed because Jwt token does not contain 'jku' header parameter.");
		}

		return matchesTokenKeyUrlDomain(tokenKeyUrl);
	}

	private ValidationResult matchesTokenKeyUrlDomain(String tokenKeyUrl) {
		URI jkuUri;
		try {
			jkuUri = new URI(tokenKeyUrl);
			if(jkuUri.getHost() != null && jkuUri.getHost().endsWith(domain)) {
				return createValid();
			}
		} catch (URISyntaxException e) {
			logger.error("Error: 'jku' header parameter '{}' does not provide a valid URI: {}.", tokenKeyUrl, e.getMessage(), e);
		}
		return createInvalid("Issuer is not trusted because 'jku' '{}' does not match uaa domain '{}' of the identity service.",
				tokenKeyUrl, domain);
	}

	@Override public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;

		XsuaaJwtIssuerValidator that = (XsuaaJwtIssuerValidator) o;

		return domain.equals(that.domain);
	}

	@Override public int hashCode() {
		return domain.hashCode();
	}
}
