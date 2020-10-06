package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import org.eclipse.jetty.servlet.ServletHolder;

import javax.servlet.Filter;
import javax.servlet.Servlet;

// TODO api -> ApplicationServerConfiguration
public interface SecurityTestApplicationServerBuilder {

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
	SecurityTestApplicationServerBuilder useApplicationServer();

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the test execution has started. Use
	 * {@link ApplicationServerOptions#forService(Service)} to obtain a
	 * configuration object that can be customized. See
	 * {@link ApplicationServerOptions} for details.
	 *
	 * @param options
	 *            custom options to configure the application server.
	 * @return the rule itself.
	 */
	SecurityTestApplicationServerBuilder useApplicationServer(ApplicationServerOptions options);

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
	SecurityTestApplicationServerBuilder addApplicationServlet(Class<? extends Servlet> servletClass, String path);

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
	SecurityTestApplicationServerBuilder addApplicationServlet(ServletHolder servletHolder, String path);

	/**
	 * Adds a filter to the servlet server. Only has an effect when used in
	 * conjunction with {@link #useApplicationServer}.
	 *
	 * @param filterClass
	 *            the filter class that should intercept with incoming requests.
	 * @return the rule itself.
	 */
	SecurityTestApplicationServerBuilder addApplicationServletFilter(Class<? extends Filter> filterClass);
}
