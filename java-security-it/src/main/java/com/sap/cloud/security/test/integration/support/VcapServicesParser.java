package com.sap.cloud.security.test.integration.support;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.json.JsonParsingException;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class VcapServicesParser {

	private static final Logger LOGGER = LoggerFactory.getLogger(VcapServicesParser.class);

	/**
	 * Reads the contents of a classpath resource given by {@param resourceName} and turns
	 * it into a {@link OAuth2ServiceConfiguration}.
	 *
	 * @param resourceName the name of classpath resource.
	 * @return the parsed {@link OAuth2ServiceConfiguration}.
	 * @throws JsonParsingException if the resource cannot be read or contains invalid data.
	 */
	public OAuth2ServiceConfiguration fromFile(String resourceName) {
		String vcapServicesJson = read(resourceName);

		JSONObject serviceBinding = findServiceBinding(new JSONObject(vcapServicesJson));
		Map<String, String> credentialsMap = extractCredentialsMap(serviceBinding);

		return OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withProperty(CFConstants.SERVICE_PLAN, serviceBinding.optString(CFConstants.SERVICE_PLAN))
				.withProperties(credentialsMap)
				.build();
	}

	/**
	 * Extracts the credentials part of the xsuaa service binding.
	 * Note that this does not work for nested structures inside the credentials block.
	 * Non string properties are converted to string.
	 * This is fine as long as relevant properties inside the credentials block
	 * are strings.
	 *
	 * @param serviceBinding the xsuaa service binding json
	 * @return the credential properties as a map.
	 */
	private Map<String, String> extractCredentialsMap(JSONObject serviceBinding) {
		JSONObject credentials = serviceBinding.optJSONObject(CFConstants.CREDENTIALS);
		Map<String, String> credentialsMap = new HashMap<>();
		for (String key : credentials.keySet()) {
			String value = credentials.optString(key);
			if (isPropertyAccepted(key, value)) {
				credentialsMap.put(key, value);
			}
		}
		return credentialsMap;
	}

	private boolean isPropertyAccepted(String key, String value) {
		if (CFConstants.CLIENT_SECRET.equals(key) && !nullOrEmpty(value)) {
			throw new VcapServiceParsingException("Client secret must not be provided!");
		}
		if (CFConstants.XSUAA.VERIFICATION_KEY.equals(key) && !nullOrEmpty(value)) {
			LOGGER.warn("Ignoring verification key from binding!");
			return false;
		}
		return true;
	}

	private JSONObject findServiceBinding(JSONObject vcapJson) {
		String xsuaaServiceName = Service.XSUAA.getCFName();
		if (vcapJson.has(xsuaaServiceName)) {
			return extractServiceBinding(vcapJson, xsuaaServiceName);
		}
		// TODO IAS support
		throw new VcapServiceParsingException("No supported binding found in VCAP_SERVICES!");
	}

	private JSONObject extractServiceBinding(JSONObject vcapJson, String serviceName) {
		JSONArray serviceBindings = vcapJson.getJSONArray(serviceName);
		if (serviceBindings.length() > 1) {
			LOGGER.warn("More than one binding found for service '{}'. Taking first one!", serviceName);
		}
		return serviceBindings.getJSONObject(0);
	}

	/**
	 * Wraps {@link IOUtils#resourceToString(String, Charset)} and rethrows {@link IOException}
	 * as {@link JsonParsingException} for convenience.
	 *
	 * @param resourceName
	 * @return the file as string.
	 */
	private String read(String resourceName) {
		try {
			return IOUtils.resourceToString(resourceName, StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new JsonParsingException(e.getMessage());
		}
	}

	public class VcapServiceParsingException extends RuntimeException {
		public VcapServiceParsingException(String message) {
			super(message);
		}
	}

	private boolean nullOrEmpty(String value) {
		return value == null || value.isEmpty();
	}
}