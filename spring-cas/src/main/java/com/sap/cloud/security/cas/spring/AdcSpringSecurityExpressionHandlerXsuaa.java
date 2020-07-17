package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Map;

import static com.sap.cloud.security.cas.spring.AdcSpringSecurityExpression.*;

/**
 * This class is only loaded in case org.springframework.security:spring-security-oauth2-resource-server
 * is provided by the consuming application.
 */
public class AdcSpringSecurityExpressionHandlerXsuaa extends DefaultMethodSecurityExpressionHandler {
	private AdcService service;
	private Logger logger = LoggerFactory.getLogger(getClass());

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
		String zoneId;
		String userId;

		if (authentication instanceof JwtAuthenticationToken) {
			Map<String, Object> attributes = ((JwtAuthenticationToken) authentication).getTokenAttributes();
			zoneId = (String) attributes.getOrDefault(ZONE_UUID_KEY, attributes.get(ZID));
			userId = (String) attributes.getOrDefault(USER_UUID_KEY, attributes.get(XSUAA_USER_ID));
			logger.debug("Extracted attribute zoneId={} and userId={} from authentication", zoneId, userId);
			return new AdcSpringSecurityExpression(authentication, zoneId, userId).withAdcService(service);
		}
		return null;
	}
}
