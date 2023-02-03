/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.TypedMapView;
import com.sap.cloud.security.config.k8s.K8sConstants;
import com.sap.cloud.security.config.k8s.K8sEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.*;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.config.cf.CFConstants.IAS.DOMAINS;
import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.UAA_DOMAIN;

/**
 * Builds an OAuth configuration ({@link OAuth2ServiceConfiguration}) for a
 * dedicated identity ({@link Service}) based on the properties applied.
 */
public class OAuth2ServiceConfigurationBuilder {

	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2ServiceConfigurationBuilder.class);
	private Service service;
	private boolean runInLegacyMode;
	private final Map<String, String> properties = new HashMap<>();
	private List<String> domains = new ArrayList<>();

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
		if (service == null) {
			throw new IllegalArgumentException("Service must not be null!");
		}
		OAuth2ServiceConfigurationBuilder instance = new OAuth2ServiceConfigurationBuilder();
		instance.service = service;
		return instance;
	}

	public static OAuth2ServiceConfigurationBuilder fromConfiguration(OAuth2ServiceConfiguration baseConfiguration) {
		OAuth2ServiceConfigurationBuilder builder = forService(baseConfiguration.getService());
		builder.withProperties(baseConfiguration.getProperties());
		return builder;
	}

	@Nullable
	public static OAuth2ServiceConfigurationBuilder fromServiceBinding(ServiceBinding b) {
		if (!b.getServiceName().isPresent()) {
			LOGGER.error("Ignores Service Binding with name {} as service name is not provided.", b.getName());
			return null; // as of now, method is never called when service name isn't given
		}

		final Service service = Service.from(b.getServiceName().get());
		if (service == null) {
			LOGGER.error("Service name {} is unknown. Could not create a OAuth2ServiceConfiguration from a service binding.", b.getServiceName().get());
			return null;
		}

		OAuth2ServiceConfigurationBuilder builder = forService(service)
				.withProperties(TypedMapView.ofCredentials(b).getEntries(String.class))
				.withProperty(SERVICE_PLAN,
						b.getServicePlan().orElse(K8sConstants.Plan.APPLICATION.name()).toUpperCase());
		switch (service) {
		case XSUAA:
			builder.withProperty(UAA_DOMAIN,
					(String) b.getCredentials().get(UAA_DOMAIN));
			break;
		case IAS:
			List<String> domains = TypedMapView.ofCredentials(b).getListView(DOMAINS).getItems(String.class);
			LOGGER.info("first domain : {}", domains.get(0));
			builder.withDomains(domains.toArray(new String[] {}));
			break;
		}

		return builder;
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
	 * X.509 certificate of identity service instance.
	 *
	 * @param certificate
	 *            PEM encoded certificate
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withCertificate(String certificate) {
		properties.put(CERTIFICATE, certificate);
		return this;
	}

	/**
	 * X.509 private key of identity service instance.
	 *
	 * @param privateKey
	 *            PEM encoded RSA private key
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withPrivateKey(String privateKey) {
		properties.put(KEY, privateKey);
		return this;
	}

	/**
	 * ClientIdentity of identity service instance.
	 *
	 * @param clientIdentity
	 *            ClientIdentity object
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withClientIdentity(ClientIdentity clientIdentity) {
		properties.put(CLIENT_ID, clientIdentity.getId());
		if (clientIdentity.isCertificateBased()) {
			properties.put(CERTIFICATE, clientIdentity.getCertificate());
			properties.put(KEY, clientIdentity.getKey());
		} else {
			properties.put(CLIENT_SECRET, clientIdentity.getSecret());
		}
		return this;
	}

	/**
	 * Base URL of the OAuth2 identity service instance. In multi tenancy scenarios
	 * this is the url where the service instance was created.
	 *
	 * @param url
	 *            base url, e.g. <a href="https://paastenant.idservice.com">...</a>
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withUrl(String url) {
		properties.put(URL, url);
		return this;
	}

	/**
	 * Cert URL of the OAuth2 identity service instance.
	 *
	 * @param url
	 *            cert url, e.g. <a href="https://paastenant.cert.idservice.com">...</a>
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withCertUrl(String url) {
		properties.put(XSUAA.CERT_URL, url);
		return this;
	}

	/**
	 * Credential type of OAuth2 configuration.
	 *
	 * @param credentialType
	 *            credential-type i.e. x509, instance_secret or binding_secret
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withCredentialType(CredentialType credentialType) {
		properties.put(XSUAA.CREDENTIAL_TYPE, credentialType.toString());
		return this;
	}

	/**
	 * Domains of the OAuth2 identity service instance. In multi tenancy scenarios
	 * this contains the domain where the service instance was created.
	 *
	 * @param domains
	 *            one or multiple domain, e.g. "idservice.com"
	 * @return this builder itself
	 */
	public OAuth2ServiceConfigurationBuilder withDomains(String... domains) {
		if (domains != null) {
			if (Service.XSUAA.equals(service) && domains.length == 1) {
				properties.put(XSUAA.UAA_DOMAIN, domains[0]);
			} else {
				this.domains = Arrays.asList(domains);
			}
		}
		return this;
	}

	public OAuth2ServiceConfigurationBuilder withProperty(String propertyName, String propertyValue) {
		properties.put(propertyName, propertyValue); // replaces values, that were already set
		return this;
	}

	public OAuth2ServiceConfigurationBuilder withProperties(Map<String, String> properties) {
		properties.forEach(this::withProperty);
		return this;
	}

	public OAuth2ServiceConfigurationBuilder runInLegacyMode(boolean isLegacyMode) {
		if (isLegacyMode && !service.equals(Service.XSUAA)) {
			throw new UnsupportedOperationException("Legacy Mode is not supported for Service " + service);
		}
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
		return new OAuth2ServiceConfigurationImpl(properties, service, domains, runInLegacyMode);
	}

	private static class OAuth2ServiceConfigurationImpl implements OAuth2ServiceConfiguration {

		private final Map<String, String> properties;
		private final boolean runInLegacyMode;
		private final Service service;
		private final List<String> domains;

		private OAuth2ServiceConfigurationImpl(@Nonnull Map<String, String> properties,
				@Nonnull Service service, List<String> domains, boolean runInLegacyMode) {
			this.properties = properties;
			this.service = service;
			this.runInLegacyMode = runInLegacyMode;
			this.domains = domains;
		}

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
			return hasProperty(URL) ? URI.create(properties.get(URL)) : null;
		}

		@Override
		public URI getCertUrl() {
			return hasProperty(XSUAA.CERT_URL) ? URI.create(properties.get(XSUAA.CERT_URL)) : null;
		}

		@Override
		public List<String> getDomains() {
			return domains;
		}

		@Override
		public String getProperty(String name) {
			return properties.get(name);
		}

		@Override
		public Map<String, String> getProperties() {
			return new HashMap<>(properties);
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
		public boolean isLegacyMode() {
			return runInLegacyMode;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o)
				return true;
			if (o == null || getClass() != o.getClass())
				return false;
			OAuth2ServiceConfigurationImpl that = (OAuth2ServiceConfigurationImpl) o;
			return runInLegacyMode == that.runInLegacyMode &&
					properties.equals(that.properties) &&
					service == that.service;
		}

		@Override
		public int hashCode() {
			return Objects.hash(properties, runInLegacyMode, service);
		}

		@Override
		public String toString() {
			return "OAuth2ServiceConfigurationImpl{" +
					"properties=" + properties +
					", service=" + service +
					", legacyMode=" + isLegacyMode() +
					'}';
		}
	}
}