package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * This class is only loaded in case org.springframework.security:spring-security-oauth2-resource-server
 * is provided by the consuming application.
 */
public class AdcSpringSecurityExpressionHandlerXsuaa extends DefaultMethodSecurityExpressionHandler {
	private AdcService service;

	private AdcSpringSecurityExpressionHandlerXsuaa() {
		// use factory methods instead
	}

	public static AdcSpringSecurityExpressionHandlerXsuaa getInstance(AdcService service) {
		AdcSpringSecurityExpressionHandlerXsuaa instance = new AdcSpringSecurityExpressionHandlerXsuaa();
		instance.service = service;
		return instance;
	}

	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(
			Authentication authentication, MethodInvocation invocation) {
		if (authentication instanceof JwtAuthenticationToken) {
			return new AdcSpringSecurityExpression((JwtAuthenticationToken) authentication).withAdcService(service);
		}
		return new AdcSpringSecurityExpression(authentication).withAdcService(service);
	}
}
