/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * Part of Auto Configuration {@link XsuaaAutoConfiguration}
 *
 * <h2>Example Usage</h2>
 *
 * <pre class="code">
 * declared on a class:
 *
 * &#64;Configuration
 * &#64;PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
 *
 * declared on attribute:
 *
 * &#64;Value("${xsuaa.url:}")
 * </pre>
 */
public class XsuaaServicePropertySourceFactory implements PropertySourceFactory {
	private static final Logger logger = LoggerFactory.getLogger(XsuaaServicePropertySourceFactory.class);

	protected static final String XSUAA_PREFIX = "xsuaa.";
	private static final String XSUAA_PROPERTIES_KEY = "xsuaa";
	public static final String CLIENT_ID = "xsuaa.clientid";
	public static final String CLIENT_SECRET = "xsuaa.clientsecret";
	public static final String URL = "xsuaa.url";
	public static final String UAA_DOMAIN = "xsuaa.uaadomain";

	private static final List<String> XSUAA_ATTRIBUTES = Arrays
			.asList("clientid", "clientsecret",
					"sburl", "tenantid", "tenantmode", "uaadomain", "url", "verificationkey", "xsappname",
					"certificate",
					"key", "credential-type", "certurl");

	@Override
	public PropertySource<?> createPropertySource(String name, EncodedResource resource) throws IOException {
		Properties properties = new Properties();
		Environment environment;
		if (resource.getResource() instanceof InputStreamResource
				|| (resource.getResource().getFilename() != null && !resource.getResource().getFilename().isEmpty())) {
			environment = Environments.readFromInput(resource.getResource().getInputStream());
		} else {
			environment = Environments.getCurrent();
		}
		if (environment.getNumberOfXsuaaConfigurations() > 1
				&& environment.getXsuaaConfigurationForTokenExchange() != null) { // TODO check for number of xsuaa and
			// ignore api plan
			throw new IllegalStateException(
					"Found more than one xsuaa bindings. Please consider unified broker plan or use com.sap.cloud.security:spring-security client library.");
		}
		if (environment.getXsuaaConfiguration() != null) {
			for (String key : XSUAA_ATTRIBUTES) {
				if (environment.getXsuaaConfiguration().hasProperty(key)) {
					properties.put(key, environment.getXsuaaConfiguration().getProperty(key));
				}
			}
		}
		logger.info("Parsed {} XSUAA properties.", properties.size());
		return create(XSUAA_PROPERTIES_KEY, properties);
	}

	/**
	 * Creates a PropertySource object for a map of xsuaa properties.
	 *
	 * @param name
	 * 		of the propertySource. Use only "xsuaa" as name in case you like to overwrite/set all properties.
	 * @param properties
	 * 		map of xsuaa properties
	 * @return created @Code{PropertySource}
	 */
	public static PropertySource create(String name, Properties properties) {
		for (final String property : properties.stringPropertyNames()) {
			if (XSUAA_ATTRIBUTES.contains(property)) {
				properties.setProperty(XSUAA_PREFIX + property, properties.remove(property).toString());
			} else {
				logger.info("Property {} is not considered as part of PropertySource.", property);
			}
		}
		return new PropertiesPropertySource(name, properties);
	}
}
