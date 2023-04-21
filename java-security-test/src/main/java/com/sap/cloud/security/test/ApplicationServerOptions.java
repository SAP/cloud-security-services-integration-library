/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.servlet.IasTokenAuthenticator;
import com.sap.cloud.security.servlet.TokenAuthenticator;
import com.sap.cloud.security.servlet.XsuaaTokenAuthenticator;
import com.sap.cloud.security.xsuaa.Assertions;

/**
 * This class is used to configure the application server to serve test servlets
 * inside the {@link SecurityTestRule}.
 */
public class ApplicationServerOptions {

	private final TokenAuthenticator tokenAuthenticator;
	private final int port;

	private ApplicationServerOptions(TokenAuthenticator tokenAuthenticator) {
		this(tokenAuthenticator, 0);
	}

	private ApplicationServerOptions(TokenAuthenticator tokenAuthenticator, int port) {
		this.tokenAuthenticator = tokenAuthenticator;
		this.port = port;
	}

	/**
	 * Creates an instance of ApplicationServerOptions. Overwrites the application
	 * id that is required by the XsuaaAudienceValidator.
	 *
	 * @param appId
	 *            the xsuaa application name e.g. myapp!t123.
	 * @param clientId
	 *            the xsuaa client id of the application
	 * @return the application server options.
	 */
	public static ApplicationServerOptions forXsuaaService(String appId, String clientId) {
		Assertions.assertHasText(appId, "appId is required by the XsuaaAudienceValidator");
		Assertions.assertHasText(clientId, "clientId is required by the XsuaaAudienceValidator");
		return new ApplicationServerOptions(
				new XsuaaTokenAuthenticator()
						.withServiceConfiguration(createServiceConfiguration(appId, clientId)));
	}

	/**
	 * Creates an instance of ApplicationServerOptions.
	 *
	 * @param service
	 *            the identity service
	 * @return the application server options.
	 */
	public static ApplicationServerOptions forService(Service service) {
		return switch (service) {
			case XSUAA -> forXsuaaService(SecurityTestRule.DEFAULT_APP_ID, SecurityTestRule.DEFAULT_CLIENT_ID);
			case IAS -> new ApplicationServerOptions(new IasTokenAuthenticator()
					.withServiceConfiguration(OAuth2ServiceConfigurationBuilder.forService(Service.IAS)
							.withClientId(SecurityTestRule.DEFAULT_CLIENT_ID)
							.withUrl("http://localhost")
							.withDomains("localhost")
							.build()));
			default ->
					throw new UnsupportedOperationException("Identity Service " + service + " is not yet supported.");
		};

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

	private static OAuth2ServiceConfiguration createServiceConfiguration(String appId, String clientId) {
		return OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(clientId)
				.withProperty(ServiceConstants.XSUAA.APP_ID, appId)
				.withProperty(ServiceConstants.XSUAA.UAA_DOMAIN, SecurityTestRule.DEFAULT_DOMAIN)
				.build();
	}

}
