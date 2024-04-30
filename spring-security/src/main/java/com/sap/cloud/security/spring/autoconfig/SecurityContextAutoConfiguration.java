/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy;

/**
 * {@link EnableAutoConfiguration} uses a
 * {@link com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy}, which keeps the
 * {@code com.sap.cloud.security.token.SecurityContext} in sync
 *
 * <p>
 * Can be disabled with {@code @EnableAutoConfiguration(exclude={SecurityContextAutoConfiguration.class})} or with
 * property {@code sap.spring.security.hybrid.auto = false}.
 */
@Configuration
@ConditionalOnProperty(name = { "sap.spring.security.hybrid.auto", "sap.spring.security.hybrid.sync_securitycontext"}, havingValue = "true", matchIfMissing = true)
@ConditionalOnMissingBean(SecurityContextHolderStrategy.class)
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE) // ensures that bean is initialized before other configurations
public class SecurityContextAutoConfiguration implements InitializingBean {

	@Override
	public void afterPropertiesSet() throws Exception {
		SecurityContextHolder.setContextHolderStrategy(new JavaSecurityContextHolderStrategy());
	}

}
