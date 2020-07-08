package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import com.sap.cloud.security.cas.client.AdcServiceRequest;
import com.sap.cloud.security.cas.client.AdcServiceRequestDefault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

/**
 */
public class AdcSpringSecurityExpression extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

	private static final String[] NO_ATTRIBUTES = new String[]{};
	private AdcService service;
	private Logger logger = LoggerFactory.getLogger(getClass());

	public AdcSpringSecurityExpression(Authentication authentication) {
		super(authentication);
		setTrustResolver(new AuthenticationTrustResolverImpl());
	}

	public AdcSpringSecurityExpression withAdcService(AdcService service) {
		this.service = service;
		return this;
	}

	//    public String getScopeExpression(String localScope) {
	//        // http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/expression/OAuth2SecurityExpressionMethods.html
	//        return "#oauth2.hasScope('" + getGlobalScope(localScope) + "')";
	//    }

	public boolean forAction(String action) {
		return forResourceAction(null, action, NO_ATTRIBUTES);
	}

	public boolean forAction(String action, String... attributes) {
		return forResourceAction(null, action, attributes);
	}

	public boolean forResource(String resource) {
		return forResourceAction(resource, null, NO_ATTRIBUTES);
	}

	public boolean forResource(String resource, String... attributes) {
		return forResourceAction(resource, null, attributes);
	}

	public boolean forResourceAction(String resource, String action) {
		return forResourceAction(resource, action, NO_ATTRIBUTES);
	}

	public boolean forResourceAction(String resource, String action, String... attributes) {
		String userId = getUserId();
		String zoneId = getZoneId(); // TODO zid claim

		AdcServiceRequest request = new AdcServiceRequestDefault(zoneId, userId)
				.withAction(action)
				.withResource(resource)
				.withAttributes(attributes);

		boolean isAuthorized = checkAuthorization(request);
		logger.info("Is user {} (zoneId {}) authorized to perform action '{}' on resource '{}' and attributes '{}' ? {}", userId, zoneId, action, resource, attributes, isAuthorized);

		return isAuthorized;
	}

	private String getUserId() {
		/*Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		OAuth2AuthenticationToken oauthAuth = (OAuth2AuthenticationToken)auth;

		// TODO IAS Support
		OidcUser user = (OidcUser) oauthAuth.getPrincipal();
		return user.getName(); // TODO update to unique user id*/
		return authentication.getName();
	}

	private String getZoneId() {
		String zoneId = null;
		if (authentication.getPrincipal() instanceof OAuth2AuthenticatedPrincipal) {
			OAuth2AuthenticatedPrincipal userPrincipal = (OAuth2AuthenticatedPrincipal)authentication.getPrincipal();
			zoneId = (String) userPrincipal.getAttributes().getOrDefault("zone_uuid", userPrincipal.getAttribute("zid")); // TODO
		}
		return zoneId; //TODO
	}

	private boolean checkAuthorization(AdcServiceRequest request) {
		try {
			return service.isUserAuthorized(request).getResult();
		} catch (Exception e) { // TODO improve
			logger.error("Error accessing ADC service.", e);
		}
		return false;
	}

	@Override public void setFilterObject(Object o) {
		Object filter = o;
	}

	@Override public Object getFilterObject() {
		return null;
	}

	@Override public void setReturnObject(Object o) {
	}

	@Override public Object getReturnObject() {
		return null;
	}

	@Override public Object getThis() {
		return null;
	}

}
