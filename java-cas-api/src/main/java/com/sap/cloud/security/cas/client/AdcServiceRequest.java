package com.sap.cloud.security.cas.client;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public interface AdcServiceRequest {
	Set<String> CLAIMS_TO_BE_IGNORED = new HashSet() {
		{
			add("aud");
			add("iss");
			add("exp");
			add("cid");
			add("sub");
		}
	};

	AdcServiceRequest withAction(String action);

	AdcServiceRequest withResource(String resource);

	AdcServiceRequest withAttribute(String attributeName, Object attributeValue);

	AdcServiceRequest withUserAttributes(Map<String, String> userAttributes);

	AdcServiceRequest withAttributes(String... attributeExpressions);

	/**
	 * // TODO remove to dedicated interface For Spring usage.
	 * 
	 * @return
	 */
	// Map<String, Object> getInput();

	String asInputJson();
}
