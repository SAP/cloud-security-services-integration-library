/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.cf;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.security.config.*;
import com.sap.cloud.security.json.JsonParsingException;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.VERIFICATION_KEY;

public class VcapServicesParser {

	private static final Logger LOGGER = LoggerFactory.getLogger(VcapServicesParser.class);

	private final OAuth2ServiceConfigurationBuilder oAuth2ServiceConfigurationBuilder;

	private VcapServicesParser(OAuth2ServiceConfiguration oAuth2ServiceConfiguration) {
		checkProperties(oAuth2ServiceConfiguration);
		this.oAuth2ServiceConfigurationBuilder = OAuth2ServiceConfigurationBuilder
				.fromConfiguration(oAuth2ServiceConfiguration)
				.withProperty(VERIFICATION_KEY, null);
	}

	/**
	 * This factory method loads the json content from the classpath resource given
	 * by {@code configurationResourceName}. Using the loaded data a new instance of
	 * {@link VcapServicesParser} is created. This instance can be used to obtain
	 * the {@link OAuth2ServiceConfigurationBuilder} with the
	 * {@link VcapServicesParser#getConfigurationBuilder()} ()} method.
	 * <p>
	 * The json content is expected to be a VCAP_SERVICES binding object in the
	 * following form:
	 *
	 * <pre>
	 * {
	 *   "xsuaa": [
	 *     {
	 *       "binding_name": null,
	 *       "credentials": {
	 *         "clientid": "clientId",
	 *         "identityzone": "uaa",
	 *      ...
	 * </pre>
	 *
	 * @param configurationResourceName
	 *            the name of classpath resource that contains the configuration
	 *            json.
	 * @return a new {@link VcapServicesParser} instance.
	 * @throws JsonParsingException
	 *             if the resource cannot be read or contains invalid data.
	 */
	public static VcapServicesParser fromFile(String configurationResourceName) {
		String vcapServicesJson = read(configurationResourceName);
		OAuth2ServiceConfiguration oAuth2ServiceConfiguration = findConfiguration(vcapServicesJson);
		return new VcapServicesParser(oAuth2ServiceConfiguration);
	}

	/**
	 * Creates the {@link OAuth2ServiceConfiguration} object from the loaded data.
	 *
	 * @return the configuration.
	 */
	public OAuth2ServiceConfiguration createConfiguration() {
		return getConfigurationBuilder().build();
	}

	/**
	 * Returns the configuration builder that contains the loaded data.
	 * 
	 * @return the {@link OAuth2ServiceConfigurationBuilder} instance
	 */
	public OAuth2ServiceConfigurationBuilder getConfigurationBuilder() {
		return oAuth2ServiceConfigurationBuilder;
	}

	private void checkProperties(OAuth2ServiceConfiguration oAuth2ServiceConfiguration) {
		if (!nullOrEmpty(oAuth2ServiceConfiguration.getProperty(VERIFICATION_KEY))) {
			LOGGER.warn("Ignoring verification key from service binding!");
		}
		if (!nullOrEmpty(oAuth2ServiceConfiguration.getClientSecret())) {
			throw new JsonParsingException("Client secret must not be provided!");
		}
	}

	/**
	 * Returns the first {@link OAuth2ServiceConfiguration} it can find from the service bindings in the given json.
	 *
	 * Multiple bindings are not supported! If VCAP_SERVICES contains more than one
	 * binding, the first one is used!
	 *
	 * @param vcapServicesJson
	 *            the json string of the service bindings.
	 * @return the extracted configuration
	 */
	private static OAuth2ServiceConfiguration findConfiguration(String vcapServicesJson) {
		Map<Service, Map<ServicePlan, OAuth2ServiceConfiguration>> serviceConfigurations =
				new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> vcapServicesJson)).getServiceConfigurations();
		List<OAuth2ServiceConfiguration> oAuth2ServiceConfigurations = serviceConfigurations
				.values()
				.stream()
				.flatMap(configurations -> configurations.values().stream())
				.collect(Collectors.toList());
		if (oAuth2ServiceConfigurations.isEmpty()) {
			throw new JsonParsingException("No supported binding found in VCAP_SERVICES!");
		} else if (oAuth2ServiceConfigurations.size() > 1) {
			LOGGER.warn("More than one binding found. Taking first one!");
		}
		return oAuth2ServiceConfigurations.get(0);
	}

	/**
	 * Wraps {@link IOUtils#resourceToString(String, Charset)} and rethrows
	 * {@link IOException} as {@link JsonParsingException} for convenience.
	 *
	 * @param resourceName
	 * @return the file as string.
	 */
	private static String read(String resourceName) {
		try {
			return IOUtils.resourceToString(resourceName, StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new IllegalArgumentException("Error reading resource file: " + e.getMessage());
		}
	}

	private static boolean nullOrEmpty(String value) {
		return value == null || value.isEmpty();
	}
}