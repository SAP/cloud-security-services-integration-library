package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.token.Token;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.*;
import org.springframework.util.Assert;

/**
 * This is an alternative to {@code ThreadLocalSecurityContextHolderStrategy}
 * which keeps the {@code com.sap.cloud.security.token.SecurityContext} in
 * synch.
 *
 * You need to set the system environment variable
 * {@code spring.security.strategy} to
 * {@code com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy}
 * <br>
 * or via <br>
 * 
 * <pre>
 * {@code
 * &#64;Bean
 * public MethodInvokingFactoryBean setJavaSecurityContextHolderStrategy() {
 * 		MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
 * 		methodInvokingFactoryBean.setTargetClass(SecurityContextHolder.class);
 * 		methodInvokingFactoryBean.setTargetMethod("setStrategyName");
 * 		methodInvokingFactoryBean.setArguments("com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy");
 * return methodInvokingFactoryBean;
 * }
 * }
 * </pre>
 * 
 * {@code SecurityContextHolder.setStrategyName("com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy")}
 */
public class JavaSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal();

	public void clearContext() {
		contextHolder.remove();
		com.sap.cloud.security.token.SecurityContext.clearToken();
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
