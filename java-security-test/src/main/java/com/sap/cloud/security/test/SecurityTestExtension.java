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
 *
 */
public class SecurityTestExtension implements ParameterResolver, BeforeAllCallback, AfterAllCallback {

	private final SecurityTest securityTest;

	public static SecurityTestExtensionBuilder builderFor(Service service) {
		return new SecurityTestExtensionBuilder(service);
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
	public void afterAll(ExtensionContext context) throws Exception {
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

	public static class SecurityTestExtensionBuilder implements SecurityTestBuilder {
		private final SecurityTest securityTest;

		public SecurityTestExtensionBuilder(Service service) {
			securityTest = new SecurityTest(service);
		}

		public SecurityTestExtension build() {
			return new SecurityTestExtension(securityTest);
		}

		@Override
		public SecurityTestExtensionBuilder setPort(int port) {
			securityTest.setPort(port);
			return this;
		}

		@Override
		public SecurityTestExtensionBuilder setKeys(String publicKeyPath, String privateKeyPath) {
			securityTest.setKeys(publicKeyPath, privateKeyPath);
			return this;
		}

		@Override
		public SecurityTestExtensionBuilder useApplicationServer() {
			securityTest.useApplicationServer();
			return this;
		}

		@Override
		public SecurityTestExtensionBuilder useApplicationServer(ApplicationServerOptions options) {
			securityTest.useApplicationServer(options);
			return this;
		}

		@Override
		public SecurityTestExtensionBuilder addApplicationServlet(Class<? extends Servlet> servletClass,
				String path) {
			securityTest.addApplicationServlet(servletClass, path);
			return this;
		}

		@Override
		public SecurityTestExtensionBuilder addApplicationServlet(ServletHolder servletHolder, String path) {
			securityTest.addApplicationServlet(servletHolder, path);
			return this;
		}

		@Override
		public SecurityTestExtensionBuilder addApplicationServletFilter(Class<? extends Filter> filterClass) {
			securityTest.addApplicationServletFilter(filterClass);
			return this;
		}
	}
}
