package com.sap.cloud.security.test;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.servlet.IasTokenAuthenticator;
import com.sap.cloud.security.servlet.TokenAuthenticator;
import com.sap.cloud.security.servlet.XsuaaTokenAuthenticator;
import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nullable;
import java.net.URI;

/**
 * This class is used to configure the application server to serve test servlets
 * inside the {@link SecurityTestRule}.
 */
public class ApplicationServerOptions {

	private final TokenAuthenticator tokenAuthenticator;
	private int port;
	private Service service;

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
	 *            the xs application name e.g. myapp!t123.
	 * @return the application server options.
	 */
	public static ApplicationServerOptions forXsuaaService(String appId, String clientId) {
		Assertions.assertHasText(appId, "xsappname is required by the XsuaaAudienceValidator");
		Assertions.assertHasText(clientId, "clientId is required by the XsuaaAudienceValidator");
		return new ApplicationServerOptions(
				new XsuaaTokenAuthenticator().withServiceConfiguration(new DummyXsuaaConfiguration(appId, clientId)));
	}

	/**
	 * Creates an instance of ApplicationServerOptions.
	 *
	 * @return the application server options.
	 */
	public static ApplicationServerOptions forService(Service service) {
		ApplicationServerOptions instance;

		switch (service) {
		case XSUAA:
			instance = forXsuaaService(SecurityTestRule.DEFAULT_APP_ID, SecurityTestRule.DEFAULT_CLIENT_ID);
			break;
		/*
		 * case IAS: instance = new ApplicationServerOptions(new
		 * IasTokenAuthenticator()); break;
		 */
		default:
			throw new UnsupportedOperationException("Identity Service " + service + " is not yet supported.");
		}
		instance.service = service;
		return instance;
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

	private static class DummyXsuaaConfiguration implements OAuth2ServiceConfiguration {

		private final String xsAppName;
		private final String clientId;

		DummyXsuaaConfiguration(String xsAppName, String clientId) {
			this.xsAppName = xsAppName;
			this.clientId = clientId;
		}

		@Override
		public String getClientId() {
			return clientId;
		}

		@Override
		public String getClientSecret() {
			return null;
		}

		@Override
		public URI getUrl() {
			return null;
		}

		@Nullable
		@Override
		public String getProperty(String name) {
			if (name.equals(CFConstants.XSUAA.APP_ID)) {
				return xsAppName;
			}
			if (name.equals(CFConstants.XSUAA.UAA_DOMAIN)) {
				return "localhost";
			}
			return null;
		}

		@Override
		public boolean hasProperty(String name) {
			return false;
		}

		@Override
		public Service getService() {
			return Service.XSUAA;
		}
	}

}
