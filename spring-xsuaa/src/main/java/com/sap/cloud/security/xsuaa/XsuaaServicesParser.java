/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

public class XsuaaServicesParser {

	private static final Logger logger = LoggerFactory.getLogger(XsuaaServicesParser.class);

	private static final String TAGS = "tags";
	private static final String CREDENTIALS = "credentials";
	private static final String VCAP_SERVICES = "VCAP_SERVICES";
	private static final String XSUAA_TAG = "xsuaa";
	private static final String K8S_XSUAA_PATH = "/etc/secrets/sapcp/xsuaa";

	private String vcapServices;
	private Map<String, Object> k8sServiceSecrets;
	private JSONObject credentialsJSON;

	public XsuaaServicesParser() {
		if (isK8sEnv()){
			k8sServiceSecrets = getK8sServiceSecrets();
		} else {
			logger.debug("CF environment detected");
			vcapServices = System.getenv().get(VCAP_SERVICES);
			if (vcapServices == null || vcapServices.isEmpty()) {
				logger.warn("Cannot extract XSUAA properties from VCAP_SERVICES environment variable.");
			}
		}
	}

	public XsuaaServicesParser(InputStream inputStream) throws IOException {
		if (isK8sEnv()){
			k8sServiceSecrets = new ObjectMapper().readValue(inputStream, Map.class);
		} else {
			logger.info("CF environment detected");
			vcapServices = IOUtils.toString(inputStream, Charsets.toCharset(UTF_8.name()));
			if (vcapServices == null || vcapServices.isEmpty()) {
				logger.warn("Cannot parse inputStream to extract XSUAA properties.");
			}
		}
	}

	public XsuaaServicesParser(String serviceConfigJson) {
		if (isK8sEnv()){
			ObjectMapper mapper = new ObjectMapper();
			try {
				k8sServiceSecrets = mapper.readValue(serviceConfigJson, Map.class);
			} catch (JsonProcessingException e) {
				logger.warn("ServiceConfigJson processing failed.");
			}
		} else {
			vcapServices = serviceConfigJson;
		}
		if (serviceConfigJson == null || serviceConfigJson.isEmpty()) {
			logger.warn("Cannot extract XSUAA properties from passed ServiceConfigurationJson.");
		}
	}

	private Map<String, Object> getK8sServiceSecrets() {
		final Map<String, Object> serviceBindingProperties = new HashMap<>();

		final File[] bindings = new File(K8S_XSUAA_PATH).listFiles();

		if (bindings != null && bindings.length == 0) {
			logger.warn("No bindings found in k8s {}", K8S_XSUAA_PATH);
			return serviceBindingProperties;
		}

		final File binding = bindings[0];
		logger.debug("Found {} k8s secret binding(s). Selecting '{}'", bindings.length, binding.getName());

		final File[] bindingFiles = new File(binding.getPath()).listFiles();

		if (bindingFiles != null && bindingFiles.length == 0) {
			logger.warn("Failed to read service configuration files from {}", binding.getPath());
			return serviceBindingProperties;
		}

		final List<File> secretProperties = Arrays.stream(bindingFiles).filter(File::isFile)
				.collect(Collectors.toList());

		for (final File property : secretProperties) {
			try {
				final List<String> lines = Files.readAllLines(Paths.get(property.getAbsolutePath()));
				serviceBindingProperties.put(property.getName(), String.join("\\n", lines));
			}
			catch (IOException ex) {
				logger.error("Failed to read secrets files", ex);
				return serviceBindingProperties;
			}
		}
		logger.debug("K8s secrets: {}", serviceBindingProperties);
		return serviceBindingProperties;
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
			String attributeString = credentialsJSON.optString(name);
			if (attributeString.isEmpty()) {
				logger.info("XSUAA VCAP_SERVICES has no attribute with name '{}'.", name);
			} else {
				return Optional.of(attributeString);
			}
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
		Properties properties;
		if(isK8sEnv()){
			properties = parseK8sSecret();
		} else {
			properties = new Properties();
			JSONObject credentialsJsonObject = parseCredentials(vcapServices);
			if (credentialsJsonObject != null) {
				Set<String> keys = credentialsJsonObject.keySet();
				for (String key : keys) {
					properties.put(key, credentialsJsonObject.get(key).toString());
				}
			}
		}
		return properties;
	}

	public Properties parseK8sSecret(){
		Properties properties = new Properties();
		Set<String> keys = k8sServiceSecrets.keySet();
		for (String key : keys) {
			properties.put(key, k8sServiceSecrets.get(key).toString());
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
			JSONObject vcapServicesJSON = new JSONObject(vcapServices);
			JSONObject xsuaaBinding = searchXsuaaBinding(vcapServicesJSON);

			if (Objects.nonNull(xsuaaBinding) && xsuaaBinding.has(CREDENTIALS)) {
				return (JSONObject) xsuaaBinding.get(CREDENTIALS);
			}
		} catch (JSONException ex) {
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

			String planName = binding.optString("plan");
			boolean isApiAccessPlan = (!planName.isEmpty() && planName.equals("apiaccess"));
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

	private static boolean isK8sEnv() {
		logger.debug("K8s environment detected");
		return System.getenv().get("KUBERNETES_SERVICE_HOST") != null;
	}
}
