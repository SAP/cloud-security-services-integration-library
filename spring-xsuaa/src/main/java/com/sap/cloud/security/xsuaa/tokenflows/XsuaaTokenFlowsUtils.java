package com.sap.cloud.security.xsuaa.tokenflows;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sap.xsa.security.container.XSTokenRequest;

import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_ADDITIONAL_AZ_ATTR;

/**
 * A utilities class providing static functions required to build the XSUAA
 * token flow REST requests.
 */
class XsuaaTokenFlowsUtils {

	XsuaaTokenFlowsUtils() {
	}

	/**
	 * Builds the additional authorities claim of the JWT. Returns null, if the
	 * request does not have any additional authorities set.
	 * 
	 * @param request
	 *            the request.
	 * @return the additional authorities claims or null, if the request has no
	 *         additional authorities set.
	 * @throws TokenFlowException
	 */
	static String buildAuthorities(XSTokenRequest request) throws TokenFlowException {
		if (request.getAdditionalAuthorizationAttributes() == null) {
			return null;
		}

		try {
			Map<String, String> additionalAuthorities = request.getAdditionalAuthorizationAttributes();
			return buildAdditionalAuthoritiesJson(additionalAuthorities);
		} catch (JsonProcessingException e) {
			throw new TokenFlowException(
					"Error mapping additional authorization attributes to JSON. See root cause exception. ", e);
		}
	}

	static String buildAdditionalAuthoritiesJson(Map<String, String> additionalAuthorities)
			throws JsonProcessingException {
		Map<String, Object> additionalAuthorizationAttributes = new HashMap<>();
		additionalAuthorizationAttributes.put(CLAIM_ADDITIONAL_AZ_ATTR, additionalAuthorities);

		String additionalAuthorizationAttributesJson = new ObjectMapper()
				.writeValueAsString(additionalAuthorizationAttributes);
		return additionalAuthorizationAttributesJson;
	}
}
