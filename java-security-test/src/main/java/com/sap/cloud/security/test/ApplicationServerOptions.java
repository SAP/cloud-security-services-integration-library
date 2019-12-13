package com.sap.cloud.security.test;

import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;

/**
 * This class is used to configure the application server to serve test servlets inside the
 * {@link SecurityIntegrationTestRule}.
 */
public class ApplicationServerOptions {

	public static ApplicationServerOptions DEFAULT =
			new ApplicationServerOptions(OAuth2TokenKeyServiceWithCache.getInstance(),
					OidcConfigurationServiceWithCache.getInstance(), 0);

	private OAuth2TokenKeyServiceWithCache tokenKeyService;
	private OidcConfigurationServiceWithCache oidcConfigurationService;
	private int port;


	/**
	 * Use this metod to configure a custom {@link OAuth2TokenKeyServiceWithCache} that will be used in the
	 * application server to retrieve token keys for the token validation.
	 * @param tokenKeyService
	 * @return
	 */
	public ApplicationServerOptions useTokenKeyService(OAuth2TokenKeyServiceWithCache tokenKeyService) {
		return new ApplicationServerOptions(tokenKeyService, oidcConfigurationService, port);
	}

	/**
	 * Use this method to configure a custom {@link OidcConfigurationServiceWithCache} that will be used
	 * in the application server.
	 * @param oidcConfigurationService the custom {@link OidcConfigurationServiceWithCache}.
	 * @return the new objects object
	 */
	public ApplicationServerOptions useOidcConfigurationService(
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		return new ApplicationServerOptions(tokenKeyService, oidcConfigurationService, port);
	}

	/**
	 * Use this method to configure a custom port the application server will listen to. If not set,
	 * the servlet server will listen on a free random port.
	 * @param port the custom port.
	 * @return the new objects object.
	 */
	public ApplicationServerOptions usePort(int port) {
		return new ApplicationServerOptions(tokenKeyService, oidcConfigurationService, port);
	}

	public OAuth2TokenKeyServiceWithCache getTokenKeyService() {
		return tokenKeyService;
	}

	public OidcConfigurationServiceWithCache getOidcConfigurationService() {
		return oidcConfigurationService;
	}

	public int getPort() {
		return port;
	}

	private ApplicationServerOptions(OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService, int port) {
		this.tokenKeyService = tokenKeyService;
		this.oidcConfigurationService = oidcConfigurationService;
		this.port = port;
	}
}
