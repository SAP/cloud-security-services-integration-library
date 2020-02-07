package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.ADCService;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

import java.net.URI;

/**
 * TODO: extract as library
 */
public class ADCSpringSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {
	private ADCService service;
	private URI adcUrl;

	private ADCSpringSecurityExpressionHandler() {
		// use factory methods instead
	}

	public static ADCSpringSecurityExpressionHandler getInstance(ADCService service, URI adcUrl) {
		ADCSpringSecurityExpressionHandler instance = new ADCSpringSecurityExpressionHandler();
		instance.service = service;
		instance.adcUrl = adcUrl;
		return instance;
	}


	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(
			Authentication authentication, MethodInvocation invocation) {
		return new ADCSpringSecurityExpression(authentication)
						.withOpenPolicyAgentService(service)
						.withAdcUri(adcUrl);
	}
}
