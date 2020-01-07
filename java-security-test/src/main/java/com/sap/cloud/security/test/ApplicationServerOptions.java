package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.servlet.IasTokenAuthenticator;
import com.sap.cloud.security.servlet.TokenAuthenticator;
import com.sap.cloud.security.servlet.XsuaaTokenAuthenticator;

/**
 * This class is used to configure the application server to serve test servlets
 * inside the {@link SecurityTestRule}.
 */
public class ApplicationServerOptions {

	private final TokenAuthenticator tokenAuthenticator;
	private int port;

	private ApplicationServerOptions(TokenAuthenticator tokenAuthenticator) {
		this(tokenAuthenticator, 0);
	}

	private ApplicationServerOptions(TokenAuthenticator tokenAuthenticator, int port) {
		this.tokenAuthenticator = tokenAuthenticator;
		this.port = port;
	}

	public static ApplicationServerOptions createOptionsForService(Service service) {
		switch (service) {
		case XSUAA:
			return new ApplicationServerOptions(new XsuaaTokenAuthenticator());
		//case IAS:
		//	return new ApplicationServerOptions(new IasTokenAuthenticator());
		default:
			throw new UnsupportedOperationException("Identity Service " + service + " is not yet supported.");
		}

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
