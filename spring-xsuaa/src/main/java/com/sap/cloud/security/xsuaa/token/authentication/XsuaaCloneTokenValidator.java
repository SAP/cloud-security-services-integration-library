package com.sap.cloud.security.xsuaa.token.authentication;

import com.sap.cloud.security.xsuaa.token.Token;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * Validates in case of clone token, that the client id matches with the xsappname of the master instance.
 */
public class XsuaaCloneTokenValidator implements OAuth2TokenValidator<Jwt> {
	private String brokerClientId;
	private String brokerXsAppName;

	public XsuaaCloneTokenValidator(String brokerClientId, String brokerXsAppName) {
		Assert.hasText(brokerClientId, "'clientid' of xsuaa instance (plan: 'broker') is required");
		Assert.hasText(brokerXsAppName, "'xsappname' of xsuaa instance (plan: 'broker') is required");
		this.brokerClientId = brokerClientId;
		this.brokerXsAppName = brokerXsAppName;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		String client_id = token.getClaimAsString(Token.CLIENT_ID);
		if (client_id == null) {
			OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
					"Jwt token must contain 'cid' (client_id)", null));
		}
		if (!brokerClientId.equals(client_id) && (brokerXsAppName.contains("!b") && client_id.contains("|"))) { // is clone token
			if (!client_id.endsWith("|" + brokerXsAppName)) {  // must match to 'xsappname' of xsuaa instance (plan: 'broker')
				return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
						"Unexpected 'cid' (client id)", null));
			}
		}
		return OAuth2TokenValidatorResult.success();
	}

}
