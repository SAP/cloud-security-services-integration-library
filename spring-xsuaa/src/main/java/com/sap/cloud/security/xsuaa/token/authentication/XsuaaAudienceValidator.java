/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token.authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import com.sap.cloud.security.xsuaa.token.TokenClaims;

/**
 * Validate audience using audience field content. In case this field is empty,
 * the audience is derived from the scope field.
 */
public class XsuaaAudienceValidator implements OAuth2TokenValidator<Jwt> {
	private final Map<String, String> appIdClientIdMap = new HashMap<>();
	private final Logger logger = LoggerFactory.getLogger(XsuaaAudienceValidator.class);

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
		String tokenClientId = token.getClaimAsString(TokenClaims.CLAIM_CLIENT_ID);
		if (!StringUtils.hasText(tokenClientId)) {
			return OAuth2TokenValidatorResult.failure(
					new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Jwt token must contain 'cid' (client_id)", null));
		}

		final Set<String> allowedAudiences = getAllowedAudiences(token);

		for (Map.Entry<String, String> xsuaaConfig : appIdClientIdMap.entrySet()) {
			if (checkMatch(xsuaaConfig.getKey(), xsuaaConfig.getValue(), tokenClientId, allowedAudiences)) {
				return OAuth2TokenValidatorResult.success();
			}
		}

		final String description = String.format("Jwt token with allowed audiences %s matches none of these: %s",
				allowedAudiences, appIdClientIdMap.keySet());
		logger.debug(description);
		return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, description, null));
	}

	private boolean checkMatch(String appId, String clientId, String tokenClientId, Set<String> allowedAudiences) {
		// case 1 : token issued by own client (or master)
		if (clientId.equals(tokenClientId) || (appId.contains("!b") && tokenClientId.endsWith("|" + appId))) {
			return true;
		}

		// case 2: foreign token
		return allowedAudiences.contains(appId);
	}

	/**
	 * Retrieve audiences from token. In case the audience list is empty, takes
	 * audiences based on the scope names.
	 *
	 * @param token Jwt token
	 * @return (empty) set of audiences
	 */
	static Set<String> getAllowedAudiences(Jwt token) {
		final Set<String> allAudiences = new HashSet<>();

		final List<String> tokenAudiences = token.getAudience();
		if (tokenAudiences != null) {
			for (String audience : tokenAudiences) {
				final String aud = audience.contains(".") ? audience.substring(0, audience.indexOf('.')) : audience;
				allAudiences.add(aud);
			}
		}

		// extract audience (app-id) from scopes
		if (allAudiences.isEmpty()) {
			for (String scope : getScopes(token)) {
				if (scope.contains(".")) {
					final String aud = scope.substring(0, scope.indexOf('.'));
					allAudiences.add(aud);
				}
			}
		}

		allAudiences.remove("");

		return allAudiences;
	}

	static List<String> getScopes(Jwt token) {
		List<String> scopes = token.getClaimAsStringList(TokenClaims.CLAIM_SCOPES);
		return scopes != null ? scopes : Collections.emptyList();
	}
}
