/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import static com.sap.cloud.security.config.ServiceConstants.IAS.DOMAINS;

/**
 * Part of Auto Configuration {@code HybridIdentityServicesAutoConfiguration}
 *
 * <h2>Example Usage</h2>
 *
 * <pre class="code">
 * declared on a class:
 *
 * &#64;Configuration
 * &#64;PropertySource(factory = IdentityServicesPropertySourceFactory.class, value = { "" })
 *
 * declared on attribute:
 *
 * &#64;Value("${xsuaa.url:}")
 * </pre>
 */
public class IdentityServicesPropertySourceFactory implements PropertySourceFactory {
	private static final Logger logger = LoggerFactory.getLogger(IdentityServicesPropertySourceFactory.class);

	protected static final String PROPERTIES_KEY = "sap.security.services";
	protected static final String XSUAA_PREFIX = "sap.security.services.xsuaa.";
	protected static final String IAS_PREFIX = "sap.security.services.identity.";

	private static final List<String> XSUAA_ATTRIBUTES = Collections.unmodifiableList(Arrays
			.asList("clientid", "clientsecret", "identityzoneid",
					"sburl", "tenantid", "tenantmode", "uaadomain", "url", "verificationkey", "xsappname",
					"certificate",
					"key", "credential-type", "certurl", "name", "plan"));

	private static final List<String> IAS_ATTRIBUTES = Collections.unmodifiableList(Arrays
			.asList("clientid", "clientsecret", "domains", "url", "name", "plan"));

	private Properties properties;

	@Override
	@SuppressWarnings("squid:S2259") // false positive
	public PropertySource<?> createPropertySource(String name, EncodedResource resource) throws IOException {
		Environment environment = Environments.getCurrent();
		if (resource != null
				&& resource.getResource().getFilename() != null && !resource.getResource().getFilename().isEmpty()) {
			environment = Environments.readFromInput(resource.getResource().getInputStream());
		}

		this.properties = new Properties();

		mapXsuaaProperties(environment);
		mapIasProperties(environment);
		logger.debug("Parsed {} properties from identity services. {}", this.properties.size(),
				this.properties.stringPropertyNames());

		return new PropertiesPropertySource(name == null ? PROPERTIES_KEY : name, this.properties);
	}

	private void mapXsuaaAttributesSingleInstance(final OAuth2ServiceConfiguration oAuth2ServiceConfiguration,
			final String prefix) {
		for (String key : XSUAA_ATTRIBUTES) {
			if (oAuth2ServiceConfiguration.hasProperty(key)) {
				this.properties.put(prefix + key, oAuth2ServiceConfiguration.getProperty(key));
			}
		}
	}

	private void mapXsuaaProperties(@Nonnull Environment environment) {
		final int numberOfXsuaaConfigurations = environment.getNumberOfXsuaaConfigurations();
		final OAuth2ServiceConfiguration xsuaaConfiguration = environment.getXsuaaConfiguration();

		if (numberOfXsuaaConfigurations == 0 || xsuaaConfiguration == null) {
			/*
			 * Case "no XSUAA service configurations or only configurations with unsupported plans"
			 */
			return;
		}

		/*
		 * Case "single XSUAA service configuration": Then we do not use an array for
		 * describing the properties.
		 */
		if (numberOfXsuaaConfigurations == 1) {
			mapXsuaaAttributesSingleInstance(xsuaaConfiguration, XSUAA_PREFIX);
			return;
		}

		/*
		 * Case "multiple XSUAA service configurations": For historic reasons, the first
		 * two items in the array have a special meaning: - Item 0 is exclusively used
		 * for environment.getXsuaaConfiguration() ("an arbitrary Xsuaa configuration"
		 * of plan "application"). - Item 1 is optionally used for
		 * environment.getXsuaaConfigurationForTokenExchange()
		 * ("an arbitrary Xsuaa configuration" of plan "broker").
		 */
		mapXsuaaAttributesSingleInstance(xsuaaConfiguration, PROPERTIES_KEY + ".xsuaa[0].");

		int position = 1;
		final OAuth2ServiceConfiguration xsuaaConfigurationForTokenExchange = environment
				.getXsuaaConfigurationForTokenExchange();
		if (xsuaaConfigurationForTokenExchange != null) {
			mapXsuaaAttributesSingleInstance(xsuaaConfigurationForTokenExchange, PROPERTIES_KEY + ".xsuaa[1].");
			position = 2;
		}

		/*
		 * For all other items coming thereafter, there is no order defined anymore.
		 * However, we must not duplicate the instances...
		 */
		final List<OAuth2ServiceConfiguration> remainingXsuaaConfigurations = environment
				.getServiceConfigurationsAsList().get(Service.XSUAA)
				.stream()
				.filter(e -> e != xsuaaConfiguration && e != xsuaaConfigurationForTokenExchange)
				.toList();

		/*
		 * Usage of ".forEach" would have been preferred here, but Closures in JDK8 do
		 * not permit accessing non-final "position".
		 */
		for (OAuth2ServiceConfiguration config : remainingXsuaaConfigurations) {
			final String prefix = String.format(PROPERTIES_KEY + ".xsuaa[%d].", position++);
			this.mapXsuaaAttributesSingleInstance(config, prefix);
		}
	}

	private void mapIasProperties(@Nonnull Environment environment) {
		final OAuth2ServiceConfiguration iasConfiguration = environment.getIasConfiguration();
		if (iasConfiguration != null) {
			for (String key : IAS_ATTRIBUTES) {
				if (iasConfiguration.hasProperty(key)) { // will not find "domains" among properties
					this.properties.put(IAS_PREFIX + key, iasConfiguration.getProperty(key));
				}
			}
			this.properties.put(IAS_PREFIX + DOMAINS, iasConfiguration.getDomains());
		}
	}

}
