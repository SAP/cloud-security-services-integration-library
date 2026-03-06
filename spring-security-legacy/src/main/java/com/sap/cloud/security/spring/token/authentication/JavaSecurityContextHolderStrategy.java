/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.util.Assert;

import com.sap.cloud.security.token.Token;

/**
 * This is an alternative to {@code ThreadLocalSecurityContextHolderStrategy} which keeps the
 * {@code com.sap.cloud.security.token.SecurityContext} in sync.
 *
 * It's included in Spring Autoconfiguration
 * {@link com.sap.cloud.security.spring.autoconfig.SecurityContextEnvironmentPostProcessor}
 * <br>
 *
 * In cases when Spring Autoconfiguration is not used it can be enabled by setting the system environment variable
 * {@code spring.security.strategy} to
 * {@code com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy}
 * <br>
 * or via <br>
 *
 * <pre>
 * {@code
 * &#64;Bean
 * public MethodInvokingFactoryBean setJavaSecurityContextHolderStrategy() {
 * 	MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
 * 	methodInvokingFactoryBean.setTargetClass(SecurityContextHolder.class);
 * 	methodInvokingFactoryBean.setTargetMethod("setStrategyName");
 * 	methodInvokingFactoryBean
 * 			.setArguments("com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy");
 * 	return methodInvokingFactoryBean;
 * }
 * }
 * </pre>
 *
 * or via <br>
 * {@code
 * SecurityContextHolder.setStrategyName("com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy")}
 */
public class JavaSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<>();

	public void clearContext() {
		contextHolder.remove();
		com.sap.cloud.security.token.SecurityContext.clear();
	}

	public SecurityContext getContext() {
		SecurityContext context = contextHolder.get();
		if (context == null) {
			context = this.createEmptyContext();
			contextHolder.set(context);
		}
		return context;
	}

	public void setContext(SecurityContext context) {
		Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
		contextHolder.set(context);

		Authentication authentication = context.getAuthentication();
		if (authentication != null) {
			Object principal = authentication.getPrincipal();
			if (principal instanceof Token) {
				com.sap.cloud.security.token.SecurityContext.setToken((Token) principal);
			}
		}
	}

	public SecurityContext createEmptyContext() {
		return new SecurityContextImpl();
	}
}
