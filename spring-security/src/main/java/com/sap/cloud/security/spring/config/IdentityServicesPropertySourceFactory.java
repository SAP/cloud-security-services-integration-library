package com.sap.cloud.security.spring.config;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.cf.CFEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;

import javax.annotation.Nonnull;

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
					"key" }));

	private static final List<String> IAS_ATTRIBUTES = Collections.unmodifiableList(Arrays
			.asList(new String[] { "clientid", "clientsecret", "domain", "url" }));

	@Override
	@SuppressWarnings("squid:S2259") // false positive
	public PropertySource<?> createPropertySource(String name, EncodedResource resource) throws IOException {
		Environment environment = CFEnvironment.getInstance();
		if (resource != null
				&& resource.getResource().getFilename() != null && !resource.getResource().getFilename().isEmpty()) {
			environment = Environments.readFromInput(resource.getResource().getInputStream());
		}
		boolean multipleXsuaaServicesBound = environment.getNumberOfXsuaaConfigurations() > 1;

		Properties properties = getXsuaaProperties(environment, multipleXsuaaServicesBound);
		properties.putAll(getIasProperties(environment));
		logger.debug("Parsed {} properties from identity services. {}", properties.size(),
				properties.stringPropertyNames());
		return new PropertiesPropertySource(PROPERTIES_KEY, properties);
	}

	@Nonnull
	private Properties getXsuaaProperties(Environment environment, boolean multipleXsuaaServicesBound) {
		Properties properties = new Properties();
		if (environment.getXsuaaConfiguration() != null) {
			String xsuaaPrefix = multipleXsuaaServicesBound ? PROPERTIES_KEY + ".xsuaa[0]." : XSUAA_PREFIX;
			for (String key : XSUAA_ATTRIBUTES) {
				if (environment.getXsuaaConfiguration().hasProperty(key)) {
					properties.put(xsuaaPrefix + key, environment.getXsuaaConfiguration().getProperty(key));
				}
			}
		}
		if (multipleXsuaaServicesBound) {
			for (String key : XSUAA_ATTRIBUTES) {
				if (environment.getXsuaaConfigurationForTokenExchange().hasProperty(key)) {
					properties.put(PROPERTIES_KEY + ".xsuaa[1]." + key,
							environment.getXsuaaConfigurationForTokenExchange().getProperty(key));
				}
			}
		}
		return properties;
	}

	@Nonnull
	private Properties getIasProperties(Environment environment) {
		Properties properties = new Properties();
		if (environment.getIasConfiguration() != null) {
			for (String key : IAS_ATTRIBUTES) {
				if (environment.getIasConfiguration().hasProperty(key)) {
					properties.put(IAS_PREFIX + key, environment.getIasConfiguration().getProperty(key));
				}
			}
		}
		return properties;
	}

}
