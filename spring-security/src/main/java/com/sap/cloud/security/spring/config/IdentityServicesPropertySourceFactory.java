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

	private static void mapXsuaaAttributesSingleInstance(Properties properties, final OAuth2ServiceConfiguration oAuth2ServiceConfiguration, final String prefix) {
		for (String key : XSUAA_ATTRIBUTES) {
			if (oAuth2ServiceConfiguration.hasProperty(key)) {
				properties.put(prefix + key, oAuth2ServiceConfiguration.getProperty(key));
			}
		}
	}
	
	@Nonnull
	private void mapXsuaaProperties(Environment environment) {
		final int numberOfXsuaaConfigurations = environment.getNumberOfXsuaaConfigurations();
		if (numberOfXsuaaConfigurations == 0) {
			return;
		}
		
		final OAuth2ServiceConfiguration xsuaaConfiguration = environment.getXsuaaConfiguration();
		if (numberOfXsuaaConfigurations == 1) {
			mapXsuaaAttributesSingleInstance(this.properties, xsuaaConfiguration, XSUAA_PREFIX);
			return;
		}
		
		mapXsuaaAttributesSingleInstance(this.properties, xsuaaConfiguration, PROPERTIES_KEY + ".xsuaa[0].");

		final OAuth2ServiceConfiguration xsuaaConfigurationForTokenExchange = environment.getXsuaaConfigurationForTokenExchange();
		if (xsuaaConfigurationForTokenExchange != null) {
			mapXsuaaAttributesSingleInstance(this.properties, xsuaaConfigurationForTokenExchange, PROPERTIES_KEY + ".xsuaa[1].");
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
