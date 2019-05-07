package com.sap.cloud.security.xsuaa;

import java.io.IOException;
import java.text.ParseException;
import java.util.Properties;

import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;

/**
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
 *
 *
 */
public class XsuaaServicePropertySourceFactory implements PropertySourceFactory {

	protected static final String XSUAA_PREFIX = "xsuaa.";
	private static final String XSUAA_PROPERTYIES_KEY = "xsuaa";
	public final String CLIENT_ID = "xsuaa.clientid";
	public final String CLIENT_SECRET = "xsuaa.clientsecret";
	public final String URL = "xsuaa.url";
	public final String UAA_DOMAIN = "xsuaa.uaadomain";

	private static final String[] XSUAA_ATTRIBUTES = new String[] { "clientid", "clientsecret", "identityzoneid",
			"sburl", "tenantid", "tenantmode", "uaadomain", "url", "verificationkey", "xsappname" };

	private Properties configurationProperties = null;

	public XsuaaServicePropertySourceFactory() {
	}

	@Override
	public PropertySource<?> createPropertySource(String name, EncodedResource resource) throws IOException {
		XsuaaServicesParser vcapServicesParser = null;
		if (configurationProperties == null) {
			if (resource != null && resource.getResource().getFilename() != null
					&& !resource.getResource().getFilename().isEmpty()) {
				vcapServicesParser = new XsuaaServicesParser(resource.getResource().getInputStream());
			} else {
				vcapServicesParser = new XsuaaServicesParser();
			}
			configurationProperties = getConfigurationProperties(vcapServicesParser);
		}

		return new PropertiesPropertySource(XSUAA_PROPERTYIES_KEY, configurationProperties);
	}

	protected Properties getConfigurationProperties(XsuaaServicesParser vcapServicesParser) throws IOException {
		try {
			Properties newConfigurationProperties = new Properties();
			for (String attributeName : XSUAA_ATTRIBUTES) {
				vcapServicesParser.getAttribute(attributeName).ifPresent(
						attributeValue -> newConfigurationProperties.put(XSUAA_PREFIX + attributeName, attributeValue));
			}
			return newConfigurationProperties;
		} catch (net.minidev.json.parser.ParseException ex) {
			throw new IOException(ex);
		}
	}
}