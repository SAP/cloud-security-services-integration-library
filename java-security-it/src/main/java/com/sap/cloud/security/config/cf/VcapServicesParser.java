package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonParsingException;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
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
		List<OAuth2ServiceConfiguration> configurations = findConfigurationsForService(Service.XSUAA, vcapServicesJson);
		if (configurations.size() > 1) {
			LOGGER.warn("More than one binding found for service '{}'. Taking first one!", Service.XSUAA);
		}
		OAuth2ServiceConfiguration oAuth2ServiceConfiguration = configurations.get(0);
		checkClientSecretNotProvided(oAuth2ServiceConfiguration);
		return overrideProperties(oAuth2ServiceConfiguration);
	}

	private OAuth2ServiceConfiguration overrideProperties(OAuth2ServiceConfiguration oAuth2ServiceConfiguration) {
		if (!nullOrEmpty(oAuth2ServiceConfiguration.getProperty(CFConstants.XSUAA.VERIFICATION_KEY))) {
			LOGGER.warn("Ignoring verification key from service binding!");
		}
		return OAuth2ServiceConfigurationBuilder.fromConfiguration(oAuth2ServiceConfiguration)
				.withProperty(CFConstants.XSUAA.VERIFICATION_KEY, null)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "localhost")
				.withUrl("http://localhost")
				.build();
	}

	private void checkClientSecretNotProvided(OAuth2ServiceConfiguration oAuth2ServiceConfiguration) {
		if (!nullOrEmpty(oAuth2ServiceConfiguration.getClientSecret())) {
			throw new JsonParsingException("Client secret must not be provided!");
		}
	}

	private List<OAuth2ServiceConfiguration> findConfigurationsForService(Service service, String vcapServicesJson) {
		Map<Service, List<OAuth2ServiceConfiguration>> serviceToConfigurations = CFEnvParser
				.loadAll(vcapServicesJson, "{}");
		List<OAuth2ServiceConfiguration> oAuth2ServiceConfigurations = serviceToConfigurations
				.getOrDefault(service, Collections.emptyList());
		if (oAuth2ServiceConfigurations.isEmpty()) {
			throw new JsonParsingException("No supported binding found in VCAP_SERVICES!");
		}
		return oAuth2ServiceConfigurations;
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

	private boolean nullOrEmpty(String value) {
		return value == null || value.isEmpty();
	}
}