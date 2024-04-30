/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
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
@ConditionalOnProperty(name = "sap.spring.security.hybrid.auto", havingValue = "true", matchIfMissing = true)
@ConditionalOnWebApplication
@ConditionalOnClass(ServletContextInitializer.class)
public class SecurityContextAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean(SecurityContextHolderStrategy.class)
	@ConditionalOnProperty(name = "sap.spring.security.hybrid.sync_securitycontext", havingValue = "true", matchIfMissing = true)
	SecurityContextSetter securityContextSetter() {
		return new SecurityContextSetter();
	}

	static class SecurityContextSetter implements InitializingBean, ServletContextInitializer, Ordered {

		@Override
		public void afterPropertiesSet() throws Exception {
			if (!(SecurityContextHolder.getContextHolderStrategy() instanceof JavaSecurityContextHolderStrategy)) {
				SecurityContextHolder.setContextHolderStrategy(new JavaSecurityContextHolderStrategy());
			}
		}

		@Override
		public void onStartup(ServletContext servletContext) throws ServletException {
			// empty, used to hook early into the initialization phase
		}

		@Override
		public int getOrder() {
			return Ordered.HIGHEST_PRECEDENCE;
		}

	}

}
