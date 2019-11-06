package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.core.Assertions;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Validate audience using audience field content. in case this field is empty,
 * the audience is derived from the scope field
 */
public class JwtAudienceValidator implements Validator<Token> {
	private static final Logger logger = LoggerFactory.getLogger(JwtAudienceValidator.class);

	private final Map<String, String> appIdClientIdMap = new HashMap<>();

	public JwtAudienceValidator(String appId, String clientId) {
		configureAnotherServiceInstance(appId, clientId);
	}

	public void configureAnotherServiceInstance(String appId, String clientId) {
		Assertions.assertNotNull(clientId, "'clientId' is required");
		Assertions.assertNotNull(appId, "'appId' is required");
		appIdClientIdMap.putIfAbsent(appId, clientId);
		logger.info("configured XsuaaAudienceValidator with appId {} and clientId {}", appId, clientId);
	}

	@Override
	public ValidationResult validate(Token token) {
		String tokenClientId = token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID);
		if (tokenClientId == null || tokenClientId.isEmpty()) {
			ValidationResults.createInvalid("Jwt token must contain 'cid' (client_id)");
		}
		List<String> allowedAudiences = getAllowedAudiences(token);

		for (Map.Entry<String, String> xsuaaConfig : appIdClientIdMap.entrySet()) {
			if (checkMatch(xsuaaConfig.getKey(), xsuaaConfig.getValue(), tokenClientId, allowedAudiences)) {
				return ValidationResults.createValid();
			}
		}
		return ValidationResults
				.createInvalid("Jwt token audience matches none of these: " + appIdClientIdMap.keySet());
	}

	private boolean checkMatch(String appId, String clientId, String tokenClientId, List<String> allowedAudiences) {
		// case 1 : token issued by own client (or master)
		if (clientId.equals(tokenClientId)
				|| (appId.contains("!b") && tokenClientId.contains("|") && tokenClientId.endsWith("|" + appId))) {
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
	static List<String> getAllowedAudiences(Token token) {
		List<String> allAudiences = new ArrayList<>();
		List<String> tokenAudiences = token.getClaimAsStringList(TokenClaims.AUDIENCE);

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
		if (allAudiences.isEmpty()) {
			for (String scope : getScopes(token)) {
				if (scope.contains(".")) {
					String aud = scope.substring(0, scope.indexOf("."));
					allAudiences.add(aud);
				}
			}
		}
		return allAudiences.stream().distinct().filter(value -> !value.isEmpty()).collect(Collectors.toList());
	}

	static List<String> getScopes(Token token) {
		List<String> scopes = token.getScopes();
		return scopes != null ? scopes : new ArrayList<>();
	}
}
