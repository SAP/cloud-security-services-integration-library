package com.sap.cloud.security.test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.rules.ExternalResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.Filter;
import javax.servlet.Servlet;


public class SecurityTestRule extends ExternalResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityTestRule.class);

	public static final String DEFAULT_APP_ID = SecurityTest.DEFAULT_APP_ID;
	public static final String DEFAULT_CLIENT_ID = SecurityTest.DEFAULT_CLIENT_ID;
	public static final String DEFAULT_DOMAIN = SecurityTest.DEFAULT_DOMAIN;

	SecurityTest base;

	private SecurityTestRule() {
		// see factory method getInstance()
	}

	/**
	 * Creates an instance of the test rule for the given service.
	 *
	 * @param service
	 *            the service for which the test rule should be created.
	 * @return the test rule instance.
	 */
	public static SecurityTestRule getInstance(Service service) {
		SecurityTestRule instance = new SecurityTestRule();
		instance.base = new SecurityTest(service);

		return instance;
	}

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the {@link #before()} method. The application server will be started
	 * with default options for the given {@link Service}, see
	 * {@link ApplicationServerOptions#forService(Service)} for details. By default
	 * the servlet server will listen on a free random port. Use
	 * {@link SecurityTestRule#useApplicationServer(ApplicationServerOptions)} to
	 * overwrite default settings. Use {@link #getApplicationServerUri()} to obtain
	 * the actual port used at runtime.
	 *
	 * @return the rule itself.
	 */
	public SecurityTestRule useApplicationServer() {
		base.useApplicationServer();
		return this;
	}

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the {@link #before()} method. Use
	 * {@link ApplicationServerOptions#forService(Service)} to obtain a
	 * configuration object that can be customized. See
	 * {@link ApplicationServerOptions} for details.
	 *
	 * @param applicationServerOptions
	 *            custom options to configure the application server.
	 * @return the rule itself.
	 */
	public SecurityTestRule useApplicationServer(ApplicationServerOptions applicationServerOptions) {
		base.useApplicationServer(applicationServerOptions);
		return this;
	}

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
	public SecurityTestRule addApplicationServlet(Class<? extends Servlet> servletClass, String path) {
		base.addApplicationServlet(servletClass, path);
		return this;
	}

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
	public SecurityTestRule addApplicationServlet(ServletHolder servletHolder, String path) {
		base.addApplicationServlet(servletHolder, path);
		return this;
	}

	/**
	 * Adds a filter to the servlet server. Only has an effect when used in
	 * conjunction with {@link #useApplicationServer}.
	 *
	 * @param filterClass
	 *            the filter class that should intercept with incoming requests.
	 * @return the rule itself.
	 */
	public SecurityTestRule addApplicationServletFilter(Class<? extends Filter> filterClass) {
		base.addApplicationServletFilter(filterClass);
		return this;
	}

	/**
	 * Overwrites the port on which the identity service mock server runs
	 * (WireMock). It needs to be configured before the {@link #before()} method. If
	 * the port is not specified or is set to 0, a free random port is chosen.
	 *
	 * @param port
	 *            the port on which the wire mock service is started.
	 * @return the rule itself.
	 */
	public SecurityTestRule setPort(int port) {
		base.setPort(port);
		return this;
	}

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
	public SecurityTestRule setKeys(String publicKeyPath, String privateKeyPath) {
		base.setKeys(publicKeyPath, privateKeyPath);
		return this;
	}

	@Override
	protected void before() throws Exception {
		base.setup(); // starts WireMock (to stub communication to identity service)
	}

	/**
	 * Note: the JwtGenerator is fully configured as part of {@link #before()}
	 * method.
	 *
	 * @return the preconfigured Jwt token generator
	 */
	public JwtGenerator getPreconfiguredJwtGenerator() {
		return base.getPreconfiguredJwtGenerator();
	}

	/**
	 * Creates a very basic token on base of the preconfigured Jwt token generator.
	 * In case you like to specify further token claims, you can make use of
	 * {@link #getPreconfiguredJwtGenerator()}
	 *
	 * @return the token.
	 */
	public Token createToken() {
		return base.createToken();
	}

	/**
	 * @deprecated use {@link #getWireMockServer()} method instead.
	 * Note that WireMockServer is the base class of WireMockRule.
	 *
	 */
	@Nullable
	@Deprecated
	public WireMockRule getWireMockRule() {
		throw new UnsupportedOperationException("Deprecated since version 2.6.0. Please use getWireMockServer instead.");
	}

	/**
	 * Allows to stub further endpoints of the identity service. Returns null if the
	 * rule is not yet initialized as part of {@link #before()} method. You can find
	 * a detailed explanation on how to configure wire mock here:
	 * http://wiremock.org/docs/getting-started/
	 *
	 * @return an instance of WireMockRule or null.
	 */
	@Nullable
	public WireMockServer getWireMockServer() {
		return base.getWireMockServer();
	}

	/**
	 * Returns the URI of the embedded jetty server or null if not specified.
	 *
	 * @return uri of the application server
	 */
	@Nullable
	public String getApplicationServerUri() {
		return base.getApplicationServerUri();
	}

	@Override
	protected void after() {
		base.tearDown();
	}

}
