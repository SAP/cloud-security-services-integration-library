package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import org.eclipse.jetty.servlet.ServletHolder;

import javax.servlet.Filter;
import javax.servlet.Servlet;

public interface SecurityTestBuilder {

	/**
	 * Overwrites the port on which the identity service mock server runs
	 * (WireMock). It needs to be configured before the test execution has started. If
	 * the port is not specified or is set to 0, a free random port is chosen.
	 *
	 * @param port
	 *            the port on which the wire mock service is started.
	 * @return the rule itself.
	 */
	SecurityTestBuilder setPort(int port);

	/**
	 * Overwrites the private/public key pair to be used. The private key is used to
	 * sign the jwt token. The public key is provided by jwks endpoint (on behalf of
	 * WireMock). Checked exceptions are caught and rethrown as runtime exceptions
	 * for test convenience.
	 *
	 * @param publicKeyPath
	 *            resource path to public key file.
	 * @param privateKeyPath
	 *            resource path to private key file.
	 * @return the rule itself.
	 */
	SecurityTestBuilder setKeys(String publicKeyPath, String privateKeyPath);

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the test execution has started. The application server will be started
	 * with default options for the given {@link Service}, see
	 * {@link ApplicationServerOptions#forService(Service)} for details. By default
	 * the servlet server will listen on a free random port. Use
	 * {@link SecurityTestRule#useApplicationServer(ApplicationServerOptions)} to
	 * overwrite default settings. Use {@code getApplicationServerUri()} to obtain
	 * the actual port used at runtime.
	 *
	 * @return the rule itself.
	 */
	SecurityTestBuilder useApplicationServer();

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the test execution has started. Use
	 * {@link ApplicationServerOptions#forService(Service)} to obtain a
	 * configuration object that can be customized. See
	 * {@link ApplicationServerOptions} for details.
	 *
	 * @param options custom options to configure the application server.
	 * @return the rule itself.
	 */
	SecurityTestBuilder useApplicationServer(ApplicationServerOptions options);

	/**
	 * Adds a servlet to the servlet server. Only has an effect when used in
	 * conjunction with {@link #useApplicationServer}.
	 *
	 * @param servletClass
	 *            the servlet class that should be served.
	 * @param path
	 *            the path on which the servlet should be served, e.g. "/*".
	 * @return the rule itself.
	 */
	SecurityTestBuilder addApplicationServlet(Class<? extends Servlet> servletClass, String path);

	/**
	 * Adds a servlet to the servlet server. Only has an effect when used in
	 * conjunction with {@link #useApplicationServer}.
	 *
	 * @param servletHolder
	 *            the servlet inside a {@link ServletHolder} that should be served.
	 * @param path
	 *            the path on which the servlet should be served, e.g. "/*".
	 * @return the rule itself.
	 */
	SecurityTestBuilder addApplicationServlet(ServletHolder servletHolder, String path);

	/**
	 * Adds a filter to the servlet server. Only has an effect when used in
	 * conjunction with {@link #useApplicationServer}.
	 *
	 * @param filterClass
	 *            the filter class that should intercept with incoming requests.
	 * @return the rule itself.
	 */
	SecurityTestBuilder addApplicationServletFilter(Class<? extends Filter> filterClass);
}
