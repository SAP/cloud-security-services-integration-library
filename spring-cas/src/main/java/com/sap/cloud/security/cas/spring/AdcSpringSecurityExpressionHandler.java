package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import static com.sap.cloud.security.cas.spring.AdcSpringSecurityExpression.*;

public class AdcSpringSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {
	private AdcService service;
	private Logger logger = LoggerFactory.getLogger(getClass());

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
		String zoneId;
		String userId;

		if (authentication.getPrincipal() instanceof OAuth2AuthenticatedPrincipal) {
			OAuth2AuthenticatedPrincipal userPrincipal = (OAuth2AuthenticatedPrincipal) authentication.getPrincipal();
			zoneId = (String) userPrincipal.getAttributes()
					.getOrDefault(ZONE_UUID_KEY, userPrincipal.getAttribute(ZID));
			userId = (String) userPrincipal.getAttributes()
					.getOrDefault(USER_UUID_KEY, userPrincipal.getAttribute("sub"));
			logger.debug("Extracted attribute zoneId={} and userId={} from principal", zoneId, userId);
			return new AdcSpringSecurityExpression(authentication, zoneId, userId).withAdcService(service);
		}
		return null;
	}
}
