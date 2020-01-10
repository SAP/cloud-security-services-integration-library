package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFConstants;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.sap.cloud.security.config.cf.CFConstants.*;

public class OAuth2ServiceConfigurationBuilder {
	private Service service;
	private final Map<String, String> properties = new HashMap<>();
	private URI url;

	public OAuth2ServiceConfigurationBuilder withService(Service service) {
		this.service = service;
		return this;
	}

	public OAuth2ServiceConfigurationBuilder withClientId(String clientId) {
		properties.put(CLIENT_ID, clientId);
		return this;
	}

	public OAuth2ServiceConfigurationBuilder withClientSecret(String clientSecret) {
		properties.put(CLIENT_SECRET, clientSecret);
		return this;
	}

	public OAuth2ServiceConfigurationBuilder withUrl(String url) {
		this.url = URI.create(url);
		return this;
	}

	public OAuth2ServiceConfigurationBuilder withProperty(String propertyName, String propertyValue) {
		properties.put(propertyName, propertyValue);
		return this;
	}

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
				return Optional.ofNullable(url).orElse(URI.create(properties.get(URL)));
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
		};

	}

}
