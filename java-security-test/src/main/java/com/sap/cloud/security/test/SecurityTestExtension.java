package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.jupiter.api.extension.*;

import javax.servlet.Filter;
import javax.servlet.Servlet;

/**
 * This class creates a
 * <a href="https://junit.org/junit5/docs/current/user-guide/#extensions">junit
 * extension</a> for {@link SecurityTest}.
 */
public class SecurityTestExtension implements ParameterResolver, BeforeAllCallback, AfterAllCallback,
		SecurityTestBuilder, SecurityTestApplicationServerBuilder {

	private final SecurityTest securityTest;

	public SecurityTestExtension() {
		securityTest = new SecurityTest(Service.XSUAA);
	}

	public static SecurityTestExtension getInstance(Service service) {
		return new SecurityTestExtension(new SecurityTest(service));
	}

	private SecurityTestExtension(SecurityTest securityTest) {
		this.securityTest = securityTest;
	}

	public SecurityTestConfiguration getConfiguration() {
		return securityTest;
	}

	@Override
	public void beforeAll(ExtensionContext context) throws Exception {
		securityTest.setup();
	}

	@Override
	public void afterAll(ExtensionContext context) {
		securityTest.tearDown();
	}

	@Override
	public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext)
			throws ParameterResolutionException {
		return parameterContext.getParameter().getType().equals(SecurityTestConfiguration.class);
	}

	@Override
	public SecurityTestConfiguration resolveParameter(ParameterContext parameterContext,
			ExtensionContext extensionContext)
			throws ParameterResolutionException {
		return securityTest;
	}

	@Override
	public SecurityTestExtension setPort(int port) {
		securityTest.setPort(port);
		return this;
	}

	@Override
	public SecurityTestExtension setKeys(String publicKeyPath, String privateKeyPath) {
		securityTest.setKeys(publicKeyPath, privateKeyPath);
		return this;
	}

	@Override
	public SecurityTestExtension useApplicationServer() {
		securityTest.useApplicationServer();
		return this;
	}

	@Override
	public SecurityTestExtension useApplicationServer(ApplicationServerOptions options) {
		securityTest.useApplicationServer(options);
		return this;
	}

	@Override
	public SecurityTestExtension addApplicationServlet(Class<? extends Servlet> servletClass,
			String path) {
		securityTest.addApplicationServlet(servletClass, path);
		return this;
	}

	@Override
	public SecurityTestExtension addApplicationServlet(ServletHolder servletHolder, String path) {
		securityTest.addApplicationServlet(servletHolder, path);
		return this;
	}

	@Override
	public SecurityTestExtension addApplicationServletFilter(Class<? extends Filter> filterClass) {
		securityTest.addApplicationServletFilter(filterClass);
		return this;
	}
}
