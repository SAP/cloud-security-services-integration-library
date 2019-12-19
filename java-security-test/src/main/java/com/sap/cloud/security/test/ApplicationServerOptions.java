package com.sap.cloud.security.test;

import com.sap.cloud.security.servlet.DefaultTokenAuthenticator;
import com.sap.cloud.security.servlet.TokenAuthenticator;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;

/**
 * This class is used to configure the application server to serve test servlets
 * inside the {@link SecurityIntegrationTestRule}.
 */
public class ApplicationServerOptions {

	private final TokenAuthenticator tokenAuthenticator;
	private int port;

	private ApplicationServerOptions(TokenAuthenticator tokenAuthenticator, int port) {
		this.tokenAuthenticator = tokenAuthenticator;
		this.port = port;
	}

	public static ApplicationServerOptions createDefault() {
		return new ApplicationServerOptions(
				new DefaultTokenAuthenticator(OAuth2TokenKeyServiceWithCache.getInstance(),
						OidcConfigurationServiceWithCache.getInstance()), 0);
	}

	/**
	 * Use this method to configure a custom {@link TokenAuthenticator} that will be
	 * used in the application server to authenticate the user via tokens retrieved
	 * in the authorization header.
	 *
	 * @param tokenAuthenticator
	 *            the custom {@link TokenAuthenticator}.
	 * @return the new configuration object.
	 */
	public ApplicationServerOptions useTokenAuthenticator(TokenAuthenticator tokenAuthenticator) {
		return new ApplicationServerOptions(tokenAuthenticator, port);
	}

	/**
	 * Use this method to configure a custom port on which the application server
	 * will listen to. If not set, the servlet server will use on a free random
	 * port.
	 *
	 * @param port
	 *            the custom port.
	 * @return the new configuration object.
	 */
	public ApplicationServerOptions usePort(int port) {
		return new ApplicationServerOptions(tokenAuthenticator, port);
	}

	public TokenAuthenticator getTokenAuthenticator() {
		return tokenAuthenticator;
	}

	public int getPort() {
		return port;
	}

}
