package com.sap.cloud.security.xsuaa.token.authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.Token;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * Validate audience using audience field content. in case this field is empty,
 * the audience is derived from the scope field
 *
 */
public class XsuaaAudienceValidator implements OAuth2TokenValidator<Jwt> {
	protected XsuaaServiceConfiguration xsuaaServiceConfiguration;
	private String brokerClientId;
	private String brokerXsAppName;


	public XsuaaAudienceValidator(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this(xsuaaServiceConfiguration, xsuaaServiceConfiguration.getClientId(), xsuaaServiceConfiguration.getAppId());
	}

	public XsuaaAudienceValidator(XsuaaServiceConfiguration xsuaaServiceConfiguration, String brokerClientId, String brokerXsAppName) {
		Assert.notNull(xsuaaServiceConfiguration, "'xsuaaServiceConfiguration' is required");
		this.xsuaaServiceConfiguration = xsuaaServiceConfiguration;
		this.brokerClientId = brokerClientId;
		this.brokerXsAppName = brokerXsAppName;
	}


	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		String client_id = token.getClaimAsString(Token.CLIENT_ID);
		if(client_id == null) {
			OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
					"Jwt token must contain 'cid' (client_id)", null));
		}

		// case 1 : token issued by own client (or master)
		if (brokerClientId.equals(client_id)
				|| (brokerXsAppName.contains("!b")
				&& client_id.contains("|")
				&& client_id.endsWith("|" + brokerXsAppName))) {
			return OAuth2TokenValidatorResult.success();
		} else {
			// case 2: foreign token
			List<String> allowedAudiences = getAllowedAudiences(token);
			if (allowedAudiences.contains(xsuaaServiceConfiguration.getAppId())) {
				return OAuth2TokenValidatorResult.success();
			} else {
				return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
						"Missing audience " + xsuaaServiceConfiguration.getAppId(), null));
			}
		}
	}


	/**
	 * Retrieve audiences from token. In case the audience list is empty, take
	 * audiences based on the scope names.
	 *
	 * @param token
	 * @return (empty) list of audiences
	 */
	static List<String> getAllowedAudiences(Jwt token) {
		List<String> allAudiences = new ArrayList<>();
		List<String> tokenAudiences = token.getAudience();

		if (tokenAudiences != null) {
			for (String audience : tokenAudiences) {
				if (audience.contains(".")) {
					String aud = audience.substring(0, audience.indexOf("."));
					allAudiences.add(aud);
				} else {
					allAudiences.add(audience);
				}
			}
		}

		// extract audience (app-id) from scopes
		if (allAudiences.size() == 0) {
			for (String scope : getScopes(token)) {
				if (scope.contains(".")) {
					String aud = scope.substring(0, scope.indexOf("."));
					allAudiences.add(aud);
				}
			}
		}
		return allAudiences.stream().distinct().filter(value -> !value.isEmpty()).collect(Collectors.toList());
	}

	static List<String> getScopes(Jwt token) {
		List<String> scopes = null;
		scopes = token.getClaimAsStringList(Token.CLAIM_SCOPES);
		return scopes != null ? scopes : new ArrayList<>();
	}
}
