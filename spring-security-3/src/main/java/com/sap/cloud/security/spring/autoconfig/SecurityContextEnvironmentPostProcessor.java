/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.security.core.context.SecurityContextHolder;

import com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy;
/**
 * Instantiates a {@link com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy}, which keeps the
 * {@code com.sap.cloud.security.token.SecurityContext} in sync
 *
 * <p>
 * Can be disabled with with property {@code sap.spring.security.hybrid.auto = false}.
 */
public class SecurityContextEnvironmentPostProcessor implements EnvironmentPostProcessor {

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
		String autoConfig = environment.getProperty("sap.spring.security.hybrid.auto");
		String syncContext = environment.getProperty("sap.spring.security.hybrid.sync_securitycontext");
		if ((autoConfig == null || Boolean.valueOf(autoConfig)) &&
				(syncContext == null || Boolean.valueOf(syncContext)) &&
				!(SecurityContextHolder.getContextHolderStrategy() instanceof JavaSecurityContextHolderStrategy)) {
			SecurityContextHolder.setContextHolderStrategy(new JavaSecurityContextHolderStrategy());
		}
	}

}
