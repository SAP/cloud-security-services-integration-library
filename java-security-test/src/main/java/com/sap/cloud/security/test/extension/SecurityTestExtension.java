/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.ApplicationServerOptions;
import com.sap.cloud.security.test.SecurityTest;
import com.sap.cloud.security.test.api.ApplicationServerConfiguration;
import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.api.ServiceMockConfiguration;
import jakarta.servlet.Filter;
import jakarta.servlet.Servlet;
import org.eclipse.jetty.ee9.servlet.ServletHolder;
import org.junit.jupiter.api.extension.*;

/**
 * This class creates a
 * <a href="https://junit.org/junit5/docs/current/user-guide/#extensions">junit
 * extension</a> for {@link SecurityTest}.
 */
public class SecurityTestExtension implements ParameterResolver, BeforeAllCallback, AfterAllCallback,
		ServiceMockConfiguration, ApplicationServerConfiguration {

	private final SecurityTest securityTest;

	SecurityTestExtension(Service service) {
		this.securityTest = new SecurityTest(service);
	}

	SecurityTestExtension(SecurityTest securityTest) {
		this.securityTest = securityTest;
	}

	public static SecurityTestExtension forService(Service service) {
		return new SecurityTestExtension(new SecurityTest(service));
	}

	public SecurityTestContext getContext() {
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
		return parameterContext.getParameter().getType().equals(SecurityTestContext.class);
	}

	@Override
	public SecurityTestContext resolveParameter(ParameterContext parameterContext,
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
