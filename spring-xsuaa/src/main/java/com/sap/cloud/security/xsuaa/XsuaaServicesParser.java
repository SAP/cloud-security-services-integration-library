package com.sap.cloud.security.xsuaa;

import static java.nio.charset.StandardCharsets.UTF_8;

import javax.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.parser.JSONParser;
import com.nimbusds.jose.shaded.json.parser.ParseException;


import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XsuaaServicesParser {

	private static final Logger logger = LoggerFactory.getLogger(XsuaaServicesParser.class);

	private static final String TAGS = "tags";
	private static final String CREDENTIALS = "credentials";
	private static final String VCAP_SERVICES = "VCAP_SERVICES";
	private static final String XSUAA_TAG = "xsuaa";

	private final String vcapServices;
	private JSONObject credentialsJSON;

	public XsuaaServicesParser() {
		vcapServices = System.getenv().get(VCAP_SERVICES);
		if (vcapServices == null || vcapServices.isEmpty()) {
			logger.warn("Cannot extract XSUAA properties from VCAP_SERVICES environment variable.");
		}
	}

	public XsuaaServicesParser(InputStream inputStream) throws IOException {
		vcapServices = IOUtils.toString(inputStream, Charsets.toCharset(UTF_8.name()));
		if (vcapServices == null || vcapServices.isEmpty()) {
			logger.warn("Cannot parse inputStream to extract XSUAA properties.");
		}
	}

	public XsuaaServicesParser(String vcapServicesJson) {
		vcapServices = vcapServicesJson;
		if (vcapServicesJson == null || vcapServicesJson.isEmpty()) {
			logger.warn("Cannot extract XSUAA properties from passed vcapServicesJson.");
		}
	}

	/**
	 * Parses the VCAP_SERVICES for xsuaa tag and returns a requested
	 * attribute/property from credentials.
	 * 
	 * @param name
	 *            the attribute name
	 * @return associated value to given tag name or null if attribute/property not
	 *         found
	 * @throws IOException
	 *             in case of parse errors
	 * @deprecated in favor of {@link #parseCredentials()}. Will be deleted with
	 *             version 3.0.0.
	 */
	@Deprecated
	public Optional<String> getAttribute(String name) throws IOException {
		if (credentialsJSON == null) {
			credentialsJSON = parseCredentials(vcapServices);
		}
		if (credentialsJSON != null) {
			Optional<String> attributeString = Optional.ofNullable(credentialsJSON.getOrDefault(name, Optional.empty()).toString());
			if (!attributeString.isPresent()) {
				logger.info("XSUAA VCAP_SERVICES has no attribute with name '{}'.", name);
			}
			return attributeString;
		}
		return Optional.empty();
	}

	/**
	 * Parses the VCAP_SERVICES for xsuaa tag and returns all credential properties.
	 *
	 * @return Properties that contains all properties that belong to the xsuaa
	 *         credentials object.
	 * @throws IOException
	 *             in case of parse errors.
	 *
	 */
	public Properties parseCredentials() throws IOException {
		Properties properties = new Properties();
		JSONObject credentialsJsonObject = parseCredentials(vcapServices);
		if (credentialsJsonObject != null) {
			Set<String> keys = credentialsJsonObject.keySet();
			for (String key : keys) {
				properties.put(key, credentialsJsonObject.get(key).toString());
			}
		}
		return properties;
	}

	@Nullable
	private static JSONObject parseCredentials(String vcapServices) throws IOException {
		if (vcapServices == null || vcapServices.isEmpty()) {
			logger.warn("VCAP_SERVICES could not be load.");
			return null;
		}
		try {
			JSONObject vcapServicesJSON = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(vcapServices);
			JSONObject xsuaaBinding = searchXsuaaBinding(vcapServicesJSON);

			if (Objects.nonNull(xsuaaBinding) && xsuaaBinding.containsKey(CREDENTIALS)) {
				return (JSONObject) xsuaaBinding.get(CREDENTIALS);
			}
		} catch (ParseException ex) {
			throw new IOException("Error while parsing XSUAA credentials from VCAP_SERVICES: {}.", ex);
		}
		return null;
	}

	@Nullable
	private static JSONObject searchXsuaaBinding(final JSONObject jsonObject) {
		for (String key : jsonObject.keySet()) {
			JSONObject foundObject = getJSONObjectFromTag((JSONArray) jsonObject.get(key), XSUAA_TAG);
			if (foundObject != null) {
				return foundObject;
			}
		}
		return null;
	}

	private static JSONObject getJSONObjectFromTag(final JSONArray jsonArray, String tag) {
		JSONObject xsuaaBinding = null;
		for (Object value : jsonArray) {
			JSONObject binding = (JSONObject) value;
			JSONArray tags = (JSONArray) binding.get(TAGS);

			Optional<String> planName = Optional.ofNullable(binding.getOrDefault("plan", Optional.empty()).toString());
			boolean isApiAccessPlan = (planName.isPresent() && planName.get().equals("apiaccess"));
			for (Object o : tags) {
				if (o.equals(tag) && !isApiAccessPlan) {
					if (xsuaaBinding == null) {
						xsuaaBinding = binding;
					} else {
						throw new IllegalStateException(
								"Found more than one xsuaa bindings. Please consider unified broker plan.");
					}
				}
			}
		}
		return xsuaaBinding;
	}
}
