package com.sap.cloud.security.xsuaa;

import java.io.IOException;
import java.util.Properties;

import net.minidev.json.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
	private final Logger logger = LoggerFactory.getLogger(getClass());
	protected static final String XSUAA_PREFIX = "xsuaa.";
	private static final String XSUAA_PROPERTYIES_KEY = "xsuaa";
	public final String CLIENT_ID = "xsuaa.clientid";
	public final String CLIENT_SECRET = "xsuaa.clientsecret";
	public final String URL = "xsuaa.url";
	public final String UAA_DOMAIN = "xsuaa.uaadomain";

	private static final String[] XSUAA_ATTRIBUTES = new String[] { "clientid", "clientsecret", "identityzoneid",
			"sburl", "tenantid", "tenantmode", "uaadomain", "url", "verificationkey", "xsappname" };

	private Properties xsuaaProperties = null;

	public XsuaaServicePropertySourceFactory() {
	}

	@Override
	public PropertySource<?> createPropertySource(String name, EncodedResource resource) throws IOException {
		XsuaaServicesParser vcapServicesParser = null;
		if (xsuaaProperties == null) {
			if (resource != null && resource.getResource().getFilename().length() > 0) {
				vcapServicesParser = new XsuaaServicesParser(resource.getResource().getInputStream());
			} else {
				vcapServicesParser = new XsuaaServicesParser();
			}
			xsuaaProperties = getConfigurationProperties(vcapServicesParser);
		}
		return new PropertiesPropertySource(XSUAA_PROPERTYIES_KEY, xsuaaProperties);
	}

	protected Properties getConfigurationProperties(XsuaaServicesParser vcapServicesParser) throws IOException {
		try {
			Properties xsuaaProperties = new Properties();
			for (String attributeName : XSUAA_ATTRIBUTES) {
				vcapServicesParser.getAttribute(attributeName).ifPresent(
						attributeValue -> xsuaaProperties.put(XSUAA_PREFIX + attributeName, attributeValue));
			}
			logger.info("Extracted {} XSUAA properties", xsuaaProperties.size());
			return xsuaaProperties;
		} catch (ParseException ex) {
			throw new IOException(ex);
		}
	}
}