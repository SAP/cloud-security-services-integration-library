package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.OpenPolicyAgentRequest;
import com.sap.cloud.security.cas.client.ADCService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * TODO: extract as library
 */
public class ADCSpringSecurityExpression extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

	private static final String[] NO_ATTRIBUTES = new String[]{};
	private ADCService service;
	private URI adcUri;

	private Logger logger = LoggerFactory.getLogger(getClass());

	public ADCSpringSecurityExpression(Authentication authentication) {
		super(authentication);
		setTrustResolver(new AuthenticationTrustResolverImpl());
	}

	public ADCSpringSecurityExpression withOpenPolicyAgentService(ADCService service) {
		this.service = service;
		return this;
	}

	public ADCSpringSecurityExpression withAdcUri(URI adcUri) {
		this.adcUri = adcUri;
		return this;
	}

	//    public String getScopeExpression(String localScope) {
	//        // http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/expression/OAuth2SecurityExpressionMethods.html
	//        return "#oauth2.hasScope('" + getGlobalScope(localScope) + "')";
	//    }

	// TODO https://github.wdf.sap.corp/CPSecurity/CAS/blob/master/architecture/AMS_DETAILS.MD#spring-security-library

	public boolean onAction(String action) {
		return onResourceAction(null, action, NO_ATTRIBUTES);
	}

	public boolean onAction(String action, String... attributes) {
		return onResourceAction(null, action, attributes);
	}

	public boolean onResource(String resource) {
		return onResourceAction(resource, null, NO_ATTRIBUTES);
	}

	public boolean onResource(String resource, String... attributes) {
		return onResourceAction(resource, null, attributes);
	}

	public boolean onResourceAction(String resource, String action) {
		return onResourceAction(resource, action, NO_ATTRIBUTES);
	}

	public boolean onResourceAction(String resource, String action, String... attributes) {
		String userId = getUserId();

		OpenPolicyAgentRequest request = new OpenPolicyAgentRequest(userId)
				.withAction(action)
				.withResource(resource)
				.withAttributes(attributes);

		boolean isAuthorized = checkAuthorization(request);
		logger.info("Is user {} authorized to perform action '{}' on resource '{}' and attributes '{}' ? {}", userId, action, resource, attributes, isAuthorized);

		return isAuthorized;
	}

	private String getUserId() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		OAuth2AuthenticationToken oauthAuth = (OAuth2AuthenticationToken)auth;

		// TODO IAS Support
		OidcUser user = (OidcUser) oauthAuth.getPrincipal();
		return user.getName(); // TODO update to unique user id
	}

	private boolean checkAuthorization(OpenPolicyAgentRequest request) {
		URI adcUri = expandPath(this.adcUri, "/v1/data/rbac/allow");
		try {
			return service.isUserAuthorized(adcUri, request).getResult();
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

	// TODO replace with UriUtil.expandPath
	private URI expandPath(URI uri, String pathToAppend) {
		try {
			String newPath = uri.getPath() + pathToAppend;
			return new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(),
					newPath, uri.getQuery(), uri.getFragment());
		} catch (URISyntaxException e) {
			logger.error("Could not set path {} in given uri {}", pathToAppend, uri);
			throw new IllegalStateException(e);
		}
	}
}
