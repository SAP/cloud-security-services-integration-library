/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.FileSystemAccessor;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;

import java.io.File;
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
 *
 */
public class XsuaaServicePropertySourceFactory implements PropertySourceFactory {
	private static final Logger logger = LoggerFactory.getLogger(XsuaaServicePropertySourceFactory.class);

	private static final FileSystemAccessor k8sFileSystemAccessor= new FileSystemAccessorDefault();

	protected static final String XSUAA_PREFIX = "xsuaa.";
	private static final String XSUAA_PROPERTIES_KEY = "xsuaa";
	public static final String CLIENT_ID = "xsuaa.clientid";
	public static final String CLIENT_SECRET = "xsuaa.clientsecret";
	public static final String URL = "xsuaa.url";
	public static final String UAA_DOMAIN = "xsuaa.uaadomain";

	private static final List<String> XSUAA_ATTRIBUTES = Arrays
			.asList("clientid", "clientsecret", "identityzoneid",
					"sburl", "tenantid", "tenantmode", "uaadomain", "url", "verificationkey", "xsappname",
					"certificate",
					"key", "credential-type", "certurl");

	@Override
	public PropertySource<?> createPropertySource(String name, EncodedResource resource) throws IOException {
		Properties properties;
		if(isK8sEnv()){
			properties = getK8sServiceSecrets();
		} else {
			XsuaaServicesParser xsuaaServicesParser;
			if (resource != null && resource.getResource().getFilename() != null
					&& !resource.getResource().getFilename().isEmpty()) {
				xsuaaServicesParser = new XsuaaServicesParser(resource.getResource().getInputStream());
			} else {
				xsuaaServicesParser = new XsuaaServicesParser();
			}
			properties = xsuaaServicesParser.parseCredentials();
		}

		logger.info("Parsed {} XSUAA properties.", properties.size());
		return create(XSUAA_PROPERTIES_KEY, properties);
	}

	/**
	 * Creates a PropertySource object for a map of xsuaa properties.
	 *
	 * @param name
	 *            of the propertySource. Use only "xsuaa" as name in case you like
	 *            to overwrite/set all properties.
	 * @param properties
	 *            map of xsuaa properties
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

	private static boolean isK8sEnv() {
		logger.debug("K8s environment detected");
		return System.getenv().get("KUBERNETES_SERVICE_HOST") != null;
	}

	private Properties getK8sServiceSecrets() {
		final Properties serviceBindingProperties = new Properties();

		final File[] bindings = k8sFileSystemAccessor.getXsuaaBindings();

		if (bindings != null && bindings.length == 0) {
			logger.warn("No bindings found in k8s");
			return serviceBindingProperties;
		}

		final File[] bindingFiles = k8sFileSystemAccessor.extractXsuaaBindingFiles(bindings);
		if (bindingFiles == null) {
			logger.warn("Failed to read xsuaa service configuration files");
			return serviceBindingProperties;
		}
		return k8sFileSystemAccessor.getXsuaaServiceProperties(bindingFiles);
	}
}
