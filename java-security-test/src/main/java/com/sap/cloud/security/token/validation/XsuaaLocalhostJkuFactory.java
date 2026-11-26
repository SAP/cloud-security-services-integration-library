package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenHeader;

/**
 * Legacy helper for test credentials using a localhost JWKS endpoint. This class MUST NOT be used outside test scope.
 *
 * @deprecated No longer registered as a ServiceLoader provider. Configure the complete mock-server base URL as
 *             uaadomain instead. Retained for compatibility with direct callers only.
 */
@Deprecated
public class XsuaaLocalhostJkuFactory implements XsuaaJkuFactory {

	@Override
	public String create(String jwt) {
		Token token = Token.create(jwt);
		String tokenJku = (String) token.getHeaders().get(TokenHeader.JWKS_URL);

		if (LocalhostUrlValidator.isLocalhostUrl(tokenJku)) {
			return tokenJku;
		}

		throw new IllegalArgumentException("JKU is not trusted because it does not target localhost.");
	}
}
