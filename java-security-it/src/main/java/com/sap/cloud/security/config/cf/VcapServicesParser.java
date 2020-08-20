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

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.VERIFICATION_KEY;

public class VcapServicesParser {

	private static final Logger LOGGER = LoggerFactory.getLogger(VcapServicesParser.class);

	private final OAuth2ServiceConfigurationBuilder oAuth2ServiceConfigurationBuilder;

	private VcapServicesParser(OAuth2ServiceConfiguration oAuth2ServiceConfiguration) {
		checkProperties(oAuth2ServiceConfiguration);
		this.oAuth2ServiceConfigurationBuilder  = OAuth2ServiceConfigurationBuilder
				.fromConfiguration(oAuth2ServiceConfiguration)
				.withProperty(VERIFICATION_KEY, null)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "localhost")
				.withUrl("http://localhost");
	}

	/**
	 * Reads the contents of a classpath resource given by {@param resourceName} and turns
	 * it into a {@link OAuth2ServiceConfiguration}.
	 *
	 * @param resourceName the name of classpath resource.
	 * @return the parsed {@link OAuth2ServiceConfiguration}.
	 * @throws JsonParsingException if the resource cannot be read or contains invalid data.
	 */
	public static VcapServicesParser fromFile(String resourceName) {
		String vcapServicesJson = read(resourceName);
		List<OAuth2ServiceConfiguration> configurations = findConfigurationsForService(Service.XSUAA, vcapServicesJson);
		if (configurations.size() > 1) {
			LOGGER.warn("More than one binding found for service '{}'. Taking first one!", Service.XSUAA);
		}
		OAuth2ServiceConfiguration oAuth2ServiceConfiguration = configurations.get(0);
		return new VcapServicesParser(oAuth2ServiceConfiguration);
	}

	public VcapServicesParser setVerificationKey(String resourceName) {
		String verificationKey = read(resourceName);
		oAuth2ServiceConfigurationBuilder.withProperty(VERIFICATION_KEY, verificationKey);
		return this;
	}

	public OAuth2ServiceConfiguration createConfiguration() {
		return oAuth2ServiceConfigurationBuilder.build();
	}

	private void checkProperties(OAuth2ServiceConfiguration oAuth2ServiceConfiguration) {
		if (!nullOrEmpty(oAuth2ServiceConfiguration.getProperty(VERIFICATION_KEY))) {
			LOGGER.warn("Ignoring verification key from service binding!");
		}
		if (!nullOrEmpty(oAuth2ServiceConfiguration.getClientSecret())) {
			throw new JsonParsingException("Client secret must not be provided!");
		}
	}

	private static List<OAuth2ServiceConfiguration> findConfigurationsForService(Service service, String vcapServicesJson) {
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
	private static String  read(String resourceName) {
		try {
			return IOUtils.resourceToString(resourceName, StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new JsonParsingException(e.getMessage());
		}
	}

	private static boolean nullOrEmpty(String value) {
		return value == null || value.isEmpty();
	}
}