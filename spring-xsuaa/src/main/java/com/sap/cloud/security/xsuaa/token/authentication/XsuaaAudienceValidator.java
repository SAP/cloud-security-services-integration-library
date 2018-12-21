package com.sap.cloud.security.xsuaa.token.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

/**
 * Validate audience using audience field content. in case this field is empty, the audience is derived from the scope field
 *
 */
public class XsuaaAudienceValidator implements OAuth2TokenValidator<Jwt> {
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;

	public XsuaaAudienceValidator(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this.xsuaaServiceConfiguration = xsuaaServiceConfiguration;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		// case 1 : token issued by own client
		if (xsuaaServiceConfiguration.getClientId().equals(token.getClaimAsString("client_id"))) {
			return OAuth2TokenValidatorResult.success();
		} else {
			// case 2: foreign token
			List<String> allowedAudiences = allowedAudiences(token);
			if (allowedAudiences.contains(xsuaaServiceConfiguration.getAppId())) {
				return OAuth2TokenValidatorResult.success();
			} else {
				return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Missing audience " + xsuaaServiceConfiguration.getAppId(), null));
			}
		}
	}

	/**
	 * Retrieve audiences from token. In case the audience list is empty, take audiences based on the scope names.
	 * 
	 * @param token
	 * @return list of audiences
	 */
	private List<String> allowedAudiences(Jwt token) {
		List<String> allAudiences = new ArrayList<>();
		if (token.getClaimAsString("aud") != null) {
			for(String audience:token.getClaimAsStringList("aud"))
			{
				if (audience.contains(".")) {
					String aud = audience.substring(0, audience.indexOf("."));
					allAudiences.add(aud);
				}
				else
				{
					allAudiences.add(audience);
				}
			}
		}

		if (allAudiences.size() == 0 && token.getClaimAsStringList("scope").size()>0) {
			for (String scope : token.getClaimAsStringList("scope")) {
				if (scope.contains(".")) {
					String aud = scope.substring(0, scope.indexOf("."));
					allAudiences.add(aud);
				}
			}
		}
		return allAudiences;
	}
}
