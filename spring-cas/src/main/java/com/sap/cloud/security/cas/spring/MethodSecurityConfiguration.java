package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@AutoConfigureAfter(name = "com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration")
public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {


	@Autowired
	MethodSecurityExpressionHandler expressionHandler;

	@Override
	protected MethodSecurityExpressionHandler createExpressionHandler() {
		return expressionHandler;
	}

	@Bean
	@ConditionalOnBean(type = "com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration")
	MethodSecurityExpressionHandler expressionHandlerXsuaa(AdcService adcService) {
		return AdcSpringSecurityExpressionHandlerXsuaa.getInstance(adcService);
	}

	@Bean
	@ConditionalOnMissingBean
	MethodSecurityExpressionHandler expressionHandler(AdcService adcService) {
		return AdcSpringSecurityExpressionHandler.getInstance(adcService);
	}

}
