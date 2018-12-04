package com.sap.cloud.security.xsuaa;

import java.io.IOException;
import java.util.Properties;

import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.EncodedResource;

public class XsuaaSpringOAuth2PropertySourceFactory extends XsuaaServicePropertySourceFactory {

	private static final String SECURITY_OAUTH2_CLIENT_CLIENT_ID = "security.oauth2.client.clientId";
	private static final String SECURITY_OAUTH2_RESOURCE_PREFER_TOKEN_INFO = "security.oauth2.resource.prefer-token-info";
	private static final String SECURITY_OAUTH2_RESOURCE_USER_INFO_URI = "security.oauth2.resource.user-info-uri";
	private static final String SECURITY_OAUTH2_CLIENT_USER_AUTHORIZATION_URI = "security.oauth2.client.userAuthorizationUri";
	private static final String SECURITY_OAUTH2_CLIENT_ACCESS_TOKEN_URI = "security.oauth2.client.accessTokenUri";
	private static final String SECURITY_OAUTH2_CLIENT_CLIENT_SECRET = "security.oauth2.client.clientSecret";

	private static final String AUTH_URL_SUFFIX = "/oauth/authorize";
	private static final String ACCESS_TOKEN_SUFFIX = "/oauth/token";
	private static final String USER_INFO_SUFFIX = "/user_info";

	private static final String SPRING_SSSO_PROPERTYIES_KEY = "xsuaa_sso";

	private static final String XSUAA_PREFIX = XsuaaServicePropertySourceFactory.XSUAA_PREFIX;
	private Properties configurationProperties = null;

	@Override
	public PropertySource<?> createPropertySource(String name, EncodedResource resource) throws IOException {
		if (configurationProperties == null) {
			configurationProperties = getConfigurationProperties();
			addSecuritySsoProperties(configurationProperties);
		}
		return new PropertiesPropertySource(SPRING_SSSO_PROPERTYIES_KEY, configurationProperties);
	}

	/**
	 * Sets:
	 * <ul>
	 * <li>security.oauth2.client.clientId: The OAuth client id. This is the id by which the OAuth provider identifies your client.</li>
	 * <li>security.oauth2.resource.prefer-token-info: Use the token info, can be set to false to use the user info.</li>
	 * <li>security.oauth2.resource.user-info-uri: URI of the user endpoint.</li>
	 * <li>security.oauth2.client.userAuthorizationUri: The uri to which the user will be redirected if the user is ever needed to authorize access to
	 * the resource. Note that this is not always required, depending on which OAuth 2 profiles are supported.</li>
	 * <li>security.oauth2.client.accessTokenUri: The URI of the provider OAuth endpoint that provides the access token.</li>
	 * <li>security.oauth2.client.clientSecret: The secret associated with the resource. By default, no secret is empty</li>
	 * </ul>
	 * 
	 * 
	 * @param configurationProperties
	 */
	private Properties addSecuritySsoProperties(Properties configurationProperties) {
		String xsuaaUrlKey = XSUAA_PREFIX + "url";
		if (configurationProperties.containsKey(xsuaaUrlKey)) {

			String xsuaaUrl = configurationProperties.getProperty(xsuaaUrlKey);

			configurationProperties.put(SECURITY_OAUTH2_CLIENT_ACCESS_TOKEN_URI, xsuaaUrl + ACCESS_TOKEN_SUFFIX);
			configurationProperties.put(SECURITY_OAUTH2_CLIENT_USER_AUTHORIZATION_URI, xsuaaUrl + AUTH_URL_SUFFIX);
			configurationProperties.put(SECURITY_OAUTH2_RESOURCE_USER_INFO_URI, xsuaaUrl + USER_INFO_SUFFIX);
			configurationProperties.put(SECURITY_OAUTH2_RESOURCE_PREFER_TOKEN_INFO, true);

		}
		String xsuaaClientIdKey = XSUAA_PREFIX + "clientid";
		if (configurationProperties.containsKey(xsuaaClientIdKey)) {
			configurationProperties.put(SECURITY_OAUTH2_CLIENT_CLIENT_ID, configurationProperties.get(xsuaaClientIdKey));
		}
		String xsuaaclientsecretKey = XSUAA_PREFIX + "clientsecret";
		if (configurationProperties.containsKey(xsuaaclientsecretKey)) {
			configurationProperties.put(SECURITY_OAUTH2_CLIENT_CLIENT_SECRET, configurationProperties.get(xsuaaclientsecretKey));
		}
		return configurationProperties;
	}

}
