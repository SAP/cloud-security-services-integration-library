package com.sap.cloud.security.config;

import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nonnull;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.config.cf.CFConstants.*;

/**
 * Builds an OAuth configuration ({@link OAuth2ServiceConfiguration}) for a
 * dedicated identity ({@link Service}) based on the properties applied.
 */
public class OAuth2ServiceConfigurationBuilder {
	private Service service;
	private boolean runInLegacyMode;
	private final Map<String, String> properties = new HashMap<>();

	private OAuth2ServiceConfigurationBuilder() {
		// use forService factory method
	}

	/**
	 * Creates a builder for a dedicated identity ({@link Service})
	 * 
	 * @param service
	 *            the service
	 * @return this builder
	 */
	public static OAuth2ServiceConfigurationBuilder forService(@Nonnull Service service) {
		Assertions.assertNotNull(service, "Service must not be null!");
		OAuth2ServiceConfigurationBuilder instance = new OAuth2ServiceConfigurationBuilder();
		instance.service = service;
		return instance;
	}

	/**
	 * Client id of identity service instance.
	 *
	 * @param clientId
	 *            client identifier
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withClientId(String clientId) {
		properties.put(CLIENT_ID, clientId);
		return this;
	}

	/**
	 * Client secret of identity service instance.
	 *
	 * @param clientSecret
	 *            client secret
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withClientSecret(String clientSecret) {
		properties.put(CLIENT_SECRET, clientSecret);
		return this;
	}

	/**
	 * Base URL of the OAuth2 identity service instance. In multi tenancy scenarios
	 * this is the url where the service instance was created.
	 *
	 * @param url
	 *            base url, e.g. https://paastenant.idservice.com
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withUrl(String url) {
		properties.put(URL, url);
		return this;
	}

	public OAuth2ServiceConfigurationBuilder withProperty(String propertyName, String propertyValue) {
		properties.put(propertyName, propertyValue); // replaces values, that were already set
		return this;
	}

	public OAuth2ServiceConfigurationBuilder withProperties(Map<String, String> properties) {
		properties.forEach((key, value) -> withProperty(key, value));
		return this;
	}

	public OAuth2ServiceConfigurationBuilder runInLegacyMode(boolean isLegacyMode) {
		this.runInLegacyMode = isLegacyMode;
		return this;
	}

	/**
	 * Builds an OAuth configuration ({@link OAuth2ServiceConfiguration}) based on
	 * the properties applied.
	 * 
	 * @return the oauth2 service configuration.
	 */
	public OAuth2ServiceConfiguration build() {
		return new OAuth2ServiceConfiguration() {

			@Override
			public String getClientId() {
				return properties.get(CLIENT_ID);
			}

			@Override
			public String getClientSecret() {
				return properties.get(CLIENT_SECRET);
			}

			@Override
			public URI getUrl() {
				return URI.create(properties.get(URL));
			}

			@Override
			public String getProperty(String name) {
				return properties.get(name);
			}

			@Override
			public boolean hasProperty(String name) {
				return properties.containsKey(name);
			}

			@Override
			public Service getService() {
				return service;
			}

			@Override
			public String getDomain() {
				if (service.equals(Service.XSUAA) && properties.containsKey(XSUAA.UAA_DOMAIN)) {
					return properties.get(XSUAA.UAA_DOMAIN);
				}
				return null;
			}

			@Override
			public boolean isLegacyMode() {
				return runInLegacyMode;
			}
		};

	}

}
