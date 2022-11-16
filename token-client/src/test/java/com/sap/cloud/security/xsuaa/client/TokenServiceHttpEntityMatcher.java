/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.CLIENT_ID;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.CLIENT_SECRET;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.sap.cloud.security.config.ClientIdentity;
import org.mockito.ArgumentMatcher;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;

public class TokenServiceHttpEntityMatcher implements ArgumentMatcher<HttpEntity> {

	private Map<String, String> expectedParameters = new HashMap<>();

	public void setGrantType(String grantType) {
		expectedParameters.put(GRANT_TYPE, grantType);
	}

	public void setClientCredentials(ClientIdentity clientIdentity) {
		expectedParameters.put(CLIENT_ID, clientIdentity.getId());
		expectedParameters.put(CLIENT_SECRET, clientIdentity.getSecret());
	}

	public void addParameters(Map<String, String> additionalParameters) {
		expectedParameters.putAll(additionalParameters);
	}

	public void addParameter(String parameterKey, String parameterValue) {
		expectedParameters.put(parameterKey, parameterValue);
	}

	@Override
	public boolean matches(HttpEntity actual) {
		boolean headerMatches = false;
		boolean bodyMatches = false;
		HttpHeaders actualHeaders = actual.getHeaders();
		Map<String, String> actualBodyParameters = convertMultiToRegularMap((MultiValueMap) actual.getBody());

		if (actualHeaders.getAccept().contains(MediaType.APPLICATION_JSON)
				&& actualHeaders.getContentType().equals(MediaType.APPLICATION_FORM_URLENCODED)) {
			headerMatches = true;
		}
		if (actualBodyParameters.size() == expectedParameters.size()) {
			for (Map.Entry<String, String> expectedParam : expectedParameters.entrySet()) {
				if (!actualBodyParameters.get(expectedParam.getKey()).equals(expectedParam.getValue())) {
					return false;
				}
			}
			bodyMatches = true;
		}
		return headerMatches && bodyMatches;
	}

	private Map<String, String> convertMultiToRegularMap(MultiValueMap<String, String> multiValueMap) {
		Map<String, String> map = new HashMap();
		if (multiValueMap == null) {
			return map;
		}
		for (Entry<String, List<String>> entry : multiValueMap.entrySet()) {
			String entryValues = String.join(",", entry.getValue());
			map.put(entry.getKey(), entryValues);
		}
		return map;
	}
}