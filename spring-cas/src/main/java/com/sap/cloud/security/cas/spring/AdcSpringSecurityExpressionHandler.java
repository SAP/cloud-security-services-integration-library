package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

public class AdcSpringSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {
	private AdcService service;

	private AdcSpringSecurityExpressionHandler() {
		// use factory methods instead
	}

	public static AdcSpringSecurityExpressionHandler getInstance(AdcService service) {
		AdcSpringSecurityExpressionHandler instance = new AdcSpringSecurityExpressionHandler();
		instance.service = service;
		return instance;
	}

	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(
			Authentication authentication, MethodInvocation invocation) {
		return new AdcSpringSecurityExpression(authentication)
						.withAdcService(service);
	}
}
