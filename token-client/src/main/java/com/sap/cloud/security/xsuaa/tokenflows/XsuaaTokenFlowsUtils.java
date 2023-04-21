/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * A utilities class providing static functions required to build the XSUAA
 * token flow REST requests.
 */
class XsuaaTokenFlowsUtils {

	static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";

	/**
	 * Builds the additional authorities claim 'az_attr' for the JWT.
	 *
	 * @param additionalAuthorities
	 *            to be added to az_attr claim.
	 * @return the additional authorities az_attr claim as a String or null if
	 *         additional authorities were null
	 */
	static String buildAdditionalAuthoritiesJson(Map<String, String> additionalAuthorities) {
		if (additionalAuthorities != null) {
			Map<String, Object> additionalAuthorizationAttributes = new HashMap<>();
			additionalAuthorizationAttributes.put(CLAIM_ADDITIONAL_AZ_ATTR, additionalAuthorities);

			JSONObject additionalAuthorizationAttributesJson = new JSONObject(additionalAuthorizationAttributes);
			return additionalAuthorizationAttributesJson.toString();
		}
		return null;
	}
}
