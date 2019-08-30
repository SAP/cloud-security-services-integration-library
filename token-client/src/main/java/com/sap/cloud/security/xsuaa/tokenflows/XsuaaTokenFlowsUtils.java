package com.sap.cloud.security.xsuaa.tokenflows;

import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;

import com.sap.xsa.security.container.XSTokenRequest;

/**
 * A utilities class providing static functions required to build the XSUAA
 * token flow REST requests.
 */
class XsuaaTokenFlowsUtils {

	static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";

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
		} catch (RuntimeException e) {
			throw new TokenFlowException(
					"Error mapping additional authorization attributes to JSON. See root cause exception. ", e);
		}
	}

	static String buildAdditionalAuthoritiesJson(Map<String, String> additionalAuthorities) {
		Map<String, Object> additionalAuthorizationAttributes = new HashMap<>();
		additionalAuthorizationAttributes.put(CLAIM_ADDITIONAL_AZ_ATTR, additionalAuthorities);

		JSONObject additionalAuthorizationAttributesJson = new JSONObject(additionalAuthorizationAttributes);
		return additionalAuthorizationAttributesJson.toString();
	}
}
