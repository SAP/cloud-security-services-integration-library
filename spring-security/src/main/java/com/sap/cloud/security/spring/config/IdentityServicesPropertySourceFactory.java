/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.sap.cloud.security.config.cf.CFConstants.IAS.DOMAINS;

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
 *
 */
public class IdentityServicesPropertySourceFactory implements PropertySourceFactory {
	private static final Logger logger = LoggerFactory.getLogger(IdentityServicesPropertySourceFactory.class);

	protected static final String PROPERTIES_KEY = "sap.security.services";
	protected static final String XSUAA_PREFIX = "sap.security.services.xsuaa.";
	protected static final String IAS_PREFIX = "sap.security.services.identity.";

	private static final List<String> XSUAA_ATTRIBUTES = Collections.unmodifiableList(Arrays
			.asList(new String[] { "clientid", "clientsecret", "identityzoneid",
					"sburl", "tenantid", "tenantmode", "uaadomain", "url", "verificationkey", "xsappname",
					"certificate",
					"key", "credential-type", "certurl" }));

	private static final List<String> IAS_ATTRIBUTES = Collections.unmodifiableList(Arrays
			.asList(new String[] { "clientid", "clientsecret", "domains", "url" }));

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

	private void mapXsuaaAttributesSingleInstance(final OAuth2ServiceConfiguration oAuth2ServiceConfiguration, final String prefix) {
		for (String key : XSUAA_ATTRIBUTES) {
			if (oAuth2ServiceConfiguration.hasProperty(key)) {
				this.properties.put(prefix + key, oAuth2ServiceConfiguration.getProperty(key));
			}
		}
	}
	
	@Nonnull
	private void mapXsuaaProperties(Environment environment) {
		final int numberOfXsuaaConfigurations = environment.getNumberOfXsuaaConfigurations();
		if (numberOfXsuaaConfigurations == 0) {
			return;
		}
		
		/*
		 * Special case: We only have exactly one XSUAA Service Configuration in place.
		 * Then we do not use an array for describing the properties.
		 */
		final OAuth2ServiceConfiguration xsuaaConfiguration = environment.getXsuaaConfiguration();
		if (numberOfXsuaaConfigurations == 1) {
			mapXsuaaAttributesSingleInstance(xsuaaConfiguration, XSUAA_PREFIX);
			return;
		}
		
		/*
		 * Case "multiple XSUAA Service Configurations": 
		 * The first two items in the array have a special meaning:
		 * - Item 0 is exclusively used for "an arbitrary Xsuaa configuration" of plan "application"
		 * - Item 1 is exclusively used for "an arbitrary Xsuaa configuration" of plan "broker"
		 */
		mapXsuaaAttributesSingleInstance(xsuaaConfiguration, PROPERTIES_KEY + ".xsuaa[0].");
		
		final OAuth2ServiceConfiguration xsuaaConfigurationForTokenExchange = environment.getXsuaaConfigurationForTokenExchange();
		if (xsuaaConfigurationForTokenExchange != null) {
			mapXsuaaAttributesSingleInstance(xsuaaConfigurationForTokenExchange, PROPERTIES_KEY + ".xsuaa[1].");
		}
		/*
		 * Note: In case no instance of plan "broker" is defined, but there are multiple
		 * instances of plan "application", then xsuaa[1] is left blank!
		 */
		
		/*
		 * For all other items coming thereafter, there is no order defined anymore.
		 * However, we must not duplicate the instances...
		 */
		final List<OAuth2ServiceConfiguration> allXsuaaConfigurations = environment.getXsuaaConfigurations();
		
		Stream<OAuth2ServiceConfiguration> xsuaaConfigurationsStream = allXsuaaConfigurations.stream();
		if (xsuaaConfiguration != null) {
			xsuaaConfigurationsStream = xsuaaConfigurationsStream.filter(e -> e != xsuaaConfiguration);
		}
		if (xsuaaConfigurationForTokenExchange != null) {
			xsuaaConfigurationsStream = xsuaaConfigurationsStream.filter(e -> e != xsuaaConfigurationForTokenExchange);
		}
		
		
		/* Usage for ".forEach" would have been preferred here,
		 * but Closures in JDK8 do not permit accessing non-final attributes.
		 */
		final List<OAuth2ServiceConfiguration> additionalOAuth2ServiceConfigurationList = xsuaaConfigurationsStream.collect(Collectors.toList());
		
		int position = 2;
		for (OAuth2ServiceConfiguration additionalOAuth2ServiceConfiguration : additionalOAuth2ServiceConfigurationList) {
			final String prefix = String.format(PROPERTIES_KEY + ".xsuaa[%d].", position++);
			this.mapXsuaaAttributesSingleInstance(additionalOAuth2ServiceConfiguration, prefix);
		}
	}

	@Nonnull
	private void mapIasProperties(Environment environment) {
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
