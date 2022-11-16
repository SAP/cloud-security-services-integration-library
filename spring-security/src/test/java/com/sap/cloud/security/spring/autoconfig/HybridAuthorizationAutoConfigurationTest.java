/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfigurations;
import com.sap.cloud.security.spring.token.authentication.XsuaaTokenAuthorizationConverter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class HybridAuthorizationAutoConfigurationTest {
	private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
			.withPropertyValues("sap.security.services.xsuaa.xsappname:theAppName")
			.withUserConfiguration(XsuaaServiceConfiguration.class, XsuaaServiceConfigurations.class,
					XsuaaServiceConfigurations.class)
			.withConfiguration(AutoConfigurations.of(HybridAuthorizationAutoConfiguration.class));

	@Test
	void autoConfigurationActive() {
		runner.run(context -> {
			assertNotNull(context.getBean(XsuaaTokenAuthorizationConverter.class));
			assertNotNull(context.getBean("xsuaaAuthConverter", Converter.class));
		});
	}

	@Test
	void autoConfigurationActiveInclProperties() {
		runner.withPropertyValues("sap.security.services.xsuaa.xsappname:theAppName",
				"sap.spring.security.hybrid.auto:true").run((context) -> {
					assertNotNull(context.getBean(XsuaaTokenAuthorizationConverter.class));
				});
	}

	@Test
	void autoConfigurationDisabledByProperty() {
		runner.withPropertyValues("sap.security.services.xsuaa.xsappname:theAppName",
				"sap.spring.security.hybrid.auto:false").run((context) -> {
					assertFalse(context.containsBean("xsuaaAuthConverter"));
				});
	}

	@Test
	void autoConfigurationDisabledForMultipleXsuaaServices() {
		WebApplicationContextRunner runner = new WebApplicationContextRunner()
				.withPropertyValues("sap.security.services.xsuaa[0].xsappname:theAppName")
				.withUserConfiguration(XsuaaServiceConfiguration.class, XsuaaServiceConfigurations.class,
						XsuaaServiceConfigurations.class)
				.withConfiguration(AutoConfigurations.of(HybridAuthorizationAutoConfiguration.class));

		runner.run(context -> {
			assertFalse(context.containsBean("xsuaaAuthConverter"));
		});
	}

	@Test
	void userConfigurationCanOverrideDefaultBeans() {
		runner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertFalse(context.containsBean("xsuaaAuthConverter"));
					assertNotNull(context.getBean("customXsuaaAuthConverter", XsuaaTokenAuthorizationConverter.class));
				});
	}

	@Configuration
	static class UserConfiguration {

		@Bean
		public XsuaaTokenAuthorizationConverter customXsuaaAuthConverter() {
			return new XsuaaTokenAuthorizationConverter("appId") {
				@Override
				public AbstractAuthenticationToken convert(Jwt jwt) {
					return null;
				}
			};
		}
	}

}
