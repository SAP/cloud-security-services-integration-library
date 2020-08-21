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
				.withProperty(VERIFICATION_KEY, null)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "localhost")
				.withUrl("http://localhost");
	}

	/**
	 * This factory method loads the json content from the classpath resource given
	 * by {@param configurationResourceName}. Using the loaded data a new instance
	 * of {@link VcapServicesParser} is created. This instance can be used to create
	 * an {@link OAuth2ServiceConfiguration} with the
	 * {@link VcapServicesParser#createConfiguration()} method.
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
	 * Loads the content classpath resource given by
	 * {@param verificationKeyResourceName} and sets it as the verification key of
	 * the {@link OAuth2ServiceConfiguration}.
	 *
	 * @param verificationKeyResourceName
	 *            the name of classpath resource.
	 * @return this builder instance
	 */
	public VcapServicesParser setVerificationKey(String verificationKeyResourceName) {
		String verificationKey = read(verificationKeyResourceName);
		oAuth2ServiceConfigurationBuilder.withProperty(VERIFICATION_KEY, verificationKey);
		return this;
	}

	/**
	 * See {@link OAuth2ServiceConfigurationBuilder#runInLegacyMode(boolean)}
	 */
	public VcapServicesParser runInLegacyMode(boolean legacyMode) {
		oAuth2ServiceConfigurationBuilder.runInLegacyMode(legacyMode);
		return this;
	}

	/**
	 * See {@link OAuth2ServiceConfigurationBuilder#withUrl(String)}
	 */
	public VcapServicesParser withUrl(String url) {
		oAuth2ServiceConfigurationBuilder.withUrl(url);
		return this;
	}

	/**
	 * Creates the {@link OAuth2ServiceConfiguration} object from the loaded data.
	 *
	 * @return the configuration.
	 */
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

	/**
	 * Uses {@link CFEnvParser} to create an {@link OAuth2ServiceConfiguration}
	 * object from the given json.
	 *
	 * Multiple bindings are not supported! If VCAP_SERVICES contains more than one
	 * binding, the first one is used!
	 *
	 * @param vcapServicesJson
	 *            the json string of the service bindings.
	 * @return the extracted configuration
	 */
	private static OAuth2ServiceConfiguration findConfiguration(String vcapServicesJson) {
		Map<Service, List<OAuth2ServiceConfiguration>> serviceToConfigurations = CFEnvParser
				.loadAll(vcapServicesJson, "{}");
		List<OAuth2ServiceConfiguration> oAuth2ServiceConfigurations = serviceToConfigurations
				.values()
				.stream()
				.flatMap(configurations -> configurations.stream())
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
			throw new JsonParsingException(e.getMessage());
		}
	}

	private static boolean nullOrEmpty(String value) {
		return value == null || value.isEmpty();
	}
}