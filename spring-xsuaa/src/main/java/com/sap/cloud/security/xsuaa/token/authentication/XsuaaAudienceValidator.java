package com.sap.cloud.security.xsuaa.token.authentication;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.sap.cloud.security.token.TokenClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServicesParser;

/**
 * Validate audience using audience field content. in case this field is empty,
 * the audience is derived from the scope field
 */
public class XsuaaAudienceValidator implements OAuth2TokenValidator<Jwt> {
	private Map<String, String> appIdClientIdMap = new HashMap<>();
	private final Logger logger = LoggerFactory.getLogger(XsuaaServicesParser.class);

	public XsuaaAudienceValidator(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		Assert.notNull(xsuaaServiceConfiguration, "'xsuaaServiceConfiguration' is required");
		appIdClientIdMap.put(xsuaaServiceConfiguration.getAppId(), xsuaaServiceConfiguration.getClientId());
	}

	public void configureAnotherXsuaaInstance(String appId, String clientId) {
		Assert.notNull(appId, "'appId' is required");
		Assert.notNull(clientId, "'clientId' is required");
		appIdClientIdMap.putIfAbsent(appId, clientId);
		logger.info("configured XsuaaAudienceValidator with appId {} and clientId {}", appId, clientId);
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		String tokenClientId = token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID);
		if (StringUtils.isEmpty(tokenClientId)) {
			return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
					"Jwt token must contain 'cid' (client_id)", null));
		}
		List<String> allowedAudiences = getAllowedAudiences(token);

		for (Map.Entry<String, String> xsuaaConfig : appIdClientIdMap.entrySet()) {
			if (checkMatch(xsuaaConfig.getKey(), xsuaaConfig.getValue(), tokenClientId, allowedAudiences)) {
				return OAuth2TokenValidatorResult.success();
			}
		}
		return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
				"Jwt token audience matches none of these: " + appIdClientIdMap.keySet().toString(), null));
	}

	private boolean checkMatch(String appId, String clientId, String tokenClientId, List<String> allowedAudiences) {
		// case 1 : token issued by own client (or master)
		if (clientId.equals(tokenClientId)
				|| (appId.contains("!b")
						&& tokenClientId.contains("|")
						&& tokenClientId.endsWith("|" + appId))) {
			return true;
		} else {
			// case 2: foreign token
			if (allowedAudiences.contains(appId)) {
				return true;
			} else {
				return false;
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
		scopes = token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
		return scopes != null ? scopes : new ArrayList<>();
	}
}
