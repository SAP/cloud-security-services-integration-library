/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy;

class SecurityContextAutoConfigurationTest {

	private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(SecurityContextAutoConfiguration.class));

	@Test
	void autoConfigurationActiveByDefault() {
		runner.run(context -> {
			assertNotNull(context.getBean("securityContextAutoConfiguration"));
			assertEquals(JavaSecurityContextHolderStrategy.class,
					SecurityContextHolder.getContextHolderStrategy().getClass());
		});
	}

	@Test
	void autoConfigurationDisabledByProperty() {
		runner.withPropertyValues("sap.spring.security.hybrid.auto:false")
				.run((context) -> assertFalse(context.containsBean("securityContextAutoConfiguration")));
	}

	@Test
	void autoConfigurationDisabledBySpecificProperty() {
		runner.withPropertyValues("sap.spring.security.hybrid.sync_securitycontext:false")
				.run((context) -> assertFalse(context.containsBean("securityContextAutoConfiguration")));
	}

	@Test
	void autoConfigurationEnabledByProperty() {
		runner.withPropertyValues("sap.spring.security.hybrid.auto:true")
				.run((context) -> assertTrue(context.containsBean("securityContextAutoConfiguration")));
	}

	@Test
	void autoConfigurationEnabledBySpecificProperty() {
		runner.withPropertyValues("sap.spring.security.hybrid.sync_securitycontext:true")
				.run((context) -> assertTrue(context.containsBean("securityContextAutoConfiguration")));
	}

	@Test
	void userConfigurationCanOverrideDefaultBeans() {
		runner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertFalse(context.containsBean("securityContextAutoConfiguration"));
					assertNotNull(context.getBean("customStrategy", SecurityContextHolderStrategy.class));
					assertNotEquals(JavaSecurityContextHolderStrategy.class,
							SecurityContextHolder.getContextHolderStrategy().getClass());
				});
	}

	@Configuration
	static class UserConfiguration {

		@Bean
		static SecurityContextHolderStrategy customStrategy() {
			SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
			return SecurityContextHolder.getContextHolderStrategy();
		}
	}
}
