/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.SecurityContextHolder;

import com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy;

class SecurityContextEnvironmentPostProcessorTest {

	private MockEnvironment env = new MockEnvironment();

	@Test
	void securityContextStrategyActiveByDefault() {
		assertStrategy(true);
	}

	@Test
	void securityContextStrategyDisabledByProperty() {
		env.setProperty("sap.spring.security.hybrid.auto", "false");
		assertStrategy(false);
	}

	@Test
	void securityContextStrategyDisabledBySpecificProperty() {
		env.setProperty("sap.spring.security.hybrid.sync_securitycontext", "false");
		assertStrategy(false);
	}

	@Test
	void securityContextStrategyEnabledByProperty() {
		env.setProperty("sap.spring.security.hybrid.auto", "true");
		assertStrategy(true);
	}

	@Test
	void securityContextStrategyEnabledBySpecificProperty() {
		env.setProperty("sap.spring.security.hybrid.sync_securitycontext", "true");
		assertStrategy(true);
	}

	void assertStrategy(boolean applied) {
		try {
			SecurityContextHolder.setStrategyName(null);
			new SecurityContextEnvironmentPostProcessor().postProcessEnvironment(env, null);
			if (applied) {
				assertTrue(SecurityContextHolder.getContextHolderStrategy() instanceof JavaSecurityContextHolderStrategy, "Expected custom strategy");
			} else {
				assertFalse(SecurityContextHolder.getContextHolderStrategy() instanceof JavaSecurityContextHolderStrategy, "Expected default strategy");
			}
		} finally {
			SecurityContextHolder.setStrategyName(null);
		}
	}

}
