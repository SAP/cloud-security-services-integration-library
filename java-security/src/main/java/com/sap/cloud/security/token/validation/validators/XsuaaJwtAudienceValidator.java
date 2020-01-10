package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.TokenClaims.*;
import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Validates if the jwt access token is intended for the OAuth2 client of this
 * application. The aud (audience) claim identifies the recipients the JWT is
 * issued for.
 *
 * Validates audience using audience field content. in case this field is empty,
 * the audience is derived from the scope field.
 */
public class XsuaaJwtAudienceValidator implements Validator<Token> {
	private static final Logger logger = LoggerFactory.getLogger(XsuaaJwtAudienceValidator.class);

	private final Map<String, String> appIdClientIdMap = new HashMap<>();

	public XsuaaJwtAudienceValidator(String appId, String clientId) {
		configureAnotherServiceInstance(appId, clientId);
	}

	public void configureAnotherServiceInstance(String appId, String clientId) {
		assertHasText(appId, "appId must not be null or empty.");
		assertHasText(clientId, "clientId must not be null or empty.");
		appIdClientIdMap.putIfAbsent(appId, clientId);
		logger.info("configured XsuaaJwtAudienceValidator with appId {} and clientId {}.", appId, clientId);
	}

	@Override
	public ValidationResult validate(Token token) {
		String tokenClientId = token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID);
		if (tokenClientId == null || tokenClientId.isEmpty()) {
			return ValidationResults.createInvalid("Jwt token must contain 'cid' (client_id).");
		}
		List<String> allowedAudiences = getAllowedAudiences(token);

		for (Map.Entry<String, String> xsuaaConfig : appIdClientIdMap.entrySet()) {
			if (checkMatch(xsuaaConfig.getKey(), xsuaaConfig.getValue(), tokenClientId, allowedAudiences)) {
				return ValidationResults.createValid();
			}
		}
		return ValidationResults
				.createInvalid("Jwt token audience matches none of these: {}.", appIdClientIdMap.keySet());
	}

	private boolean checkMatch(String appId, String clientId, String tokenClientId, List<String> allowedAudiences) {
		// case 1 : token issued by own client (or master)
		if (clientId.equals(tokenClientId)
				|| (appId.contains("!b") && tokenClientId.contains("|") && tokenClientId.endsWith("|" + appId))) {
			return true;
		} else {
			// case 2: foreign token
			return allowedAudiences.contains(appId);
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
		List<String> tokenAudiences = token.getClaimAsStringList(AUDIENCE);

		if (tokenAudiences != null) {
			for (String audience : tokenAudiences) {
				int index = audience.indexOf('.');
				if (index > -1) {
					String aud = audience.substring(0, index);
					allAudiences.add(aud);
				} else {
					allAudiences.add(audience);
				}
			}
		}

		// fallback: extract audience (app-id) from scopes
		if (allAudiences.isEmpty()) {
			for (String scope : getScopes(token)) {
				int idx = scope.indexOf('.');
				if (idx > -1) {
					String aud = scope.substring(0, idx);
					allAudiences.add(aud);
				}
			}
		}
		return allAudiences.stream().distinct().filter(value -> !value.isEmpty()).collect(Collectors.toList());
	}

	static List<String> getScopes(Token token) {
		List<String> scopes = token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
		return scopes != null ? scopes : Collections.emptyList();
	}
}
