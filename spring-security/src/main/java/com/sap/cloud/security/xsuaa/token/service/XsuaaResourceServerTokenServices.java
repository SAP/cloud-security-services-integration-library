/**
 * 
 */
package com.sap.cloud.security.xsuaa.token.service;


import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.Cache.ValueWrapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;

import com.sap.cloud.security.xsuaa.api.AuthorizationMapper;
import com.sap.cloud.security.xsuaa.api.ClaimConstants;
import com.sap.cloud.security.xsuaa.api.PostValidationAction;
import com.sap.cloud.security.xsuaa.api.TokenValidator;
import com.sap.cloud.security.xsuaa.token.jwt.JsonUtils;
import com.sap.cloud.security.xsuaa.token.jwt.UaaTokenUtils;
import com.sap.cloud.security.xsuaa.token.service.exceptions.TokenValidationException;

public class XsuaaResourceServerTokenServices implements ResourceServerTokenServices {

	private final static Log logger = LogFactory.getLog(XsuaaResourceServerTokenServices.class);

	private AuthorizationMapper authorizationMapper;
	private Cache tokenCache;
	private TokenValidator[] tokenValidators;
	private boolean storeClaims = false;
	private String xsAppName;

	public XsuaaResourceServerTokenServices(Cache tokenCache, String xsAppName, TokenValidator... tokenValidators) {
		this(tokenCache, null, xsAppName, tokenValidators);
	}

	public XsuaaResourceServerTokenServices(Cache tokenCache, AuthorizationMapper authorizationMapper, String xsAppName, TokenValidator... tokenValidators) {
		this.tokenCache = tokenCache;
		this.tokenValidators = tokenValidators;
		this.xsAppName = xsAppName;
		this.authorizationMapper = authorizationMapper;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.oauth2.provider.token.ResourceServerTokenServices#loadAuthentication(java.lang.String)
	 */
	@Override
	public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException, InvalidTokenException {
		logger.debug("Try to load Authentication for Token " + accessTokenValue);
		try {
			AuthenticationHolder cachedAuthInfo = getCachedAuthentication(accessTokenValue);
			if (cachedAuthInfo != null) {
				cachedAuthInfo.getPostValidationAction().apply();
				return cachedAuthInfo.getAuthentication();
			}
			for (TokenValidator tokenValidator : tokenValidators) {
				if (tokenValidator.isApplicable(accessTokenValue)) {
					Map<String, Object> tokenMap = tokenValidator.validateToken(accessTokenValue);
					PostValidationAction postValidationAction = tokenValidator.getPostValidationAction(tokenMap);
					postValidationAction.apply();
					OAuth2Authentication authentication = createOAuth2Authentication(tokenMap, accessTokenValue);

					Long expiration = UaaTokenUtils.getTokenExpiration(tokenMap);

					if (!UaaTokenUtils.isPlatformToken(tokenMap)) {
						// Platform token can has different identity zones -> so don't cache this
						tokenCache.put(accessTokenValue, new AuthenticationHolder(authentication, expiration, postValidationAction));
					}

					return authentication;
				}
			}
			throw new InvalidTokenException("No applicable TokenValidator was found.");
		} catch (TokenValidationException e) {
			logger.error("Cannot check the given token: " + e.getMessage(), e);
			throw new InvalidTokenException("Cannot check the given token: " + e.getMessage(), e);
		}
	}

	private OAuth2Authentication createOAuth2Authentication(Map<String, Object> tokenMap, String accessToken) {

		if (tokenMap.containsKey("error")) {
			logger.debug("check_token returned error: " + tokenMap.get("error"));
			throw new InvalidTokenException(accessToken);
		}

		Assert.state(tokenMap.containsKey("client_id"), "Client id must be present in response from auth server");
		String remoteClientId = (String) tokenMap.get("client_id");

		Set<String> scopes = new HashSet<String>();
		if (tokenMap.containsKey("scope")) {
			@SuppressWarnings("unchecked")
			Collection<String> values = (Collection<String>) tokenMap.get("scope");
			scopes.addAll(values);

			if (getAuthorizationMapper() != null) {
				logger.debug("Using Scope-Mapping");
				scopes = getAuthorizationMapper().filterScopes(tokenMap, scopes);
				tokenMap.put("scope", scopes); // override old values
			}
		}
		AuthorizationRequest clientAuthentication = new AuthorizationRequest(remoteClientId, scopes);

		if (tokenMap.containsKey("resource_ids") || tokenMap.containsKey("client_authorities")) {
			Set<String> resourceIds = new HashSet<String>();
			if (tokenMap.containsKey("resource_ids")) {
				@SuppressWarnings("unchecked")
				Collection<String> values = (Collection<String>) tokenMap.get("resource_ids");
				resourceIds.addAll(values);
			}
			Set<GrantedAuthority> clientAuthorities = new HashSet<GrantedAuthority>();
			if (tokenMap.containsKey("client_authorities")) {
				@SuppressWarnings("unchecked")
				Collection<String> values = (Collection<String>) tokenMap.get("client_authorities");

				if (getAuthorizationMapper() != null) {
					logger.debug("Using Authority-Mapping");
					clientAuthorities = getAuthorizationMapper().filterAuthorities(tokenMap, clientAuthorities);
				}

				clientAuthorities.addAll(getAuthorities(values));
			}
			BaseClientDetails clientDetails = new BaseClientDetails();
			clientDetails.setClientId(remoteClientId);
			clientDetails.setResourceIds(resourceIds);
			clientDetails.setAuthorities(clientAuthorities);
			clientAuthentication.setResourceIdsAndAuthoritiesFromClientDetails(clientDetails);
		}
		Map<String, String> requestParameters = new HashMap<>();
		if (isStoreClaims()) {
			for (Map.Entry<String, Object> entry : tokenMap.entrySet()) {
				if (entry.getValue() != null && entry.getValue() instanceof String) {
					requestParameters.put(entry.getKey(), (String) entry.getValue());
				}
			}
		}

		if (tokenMap.containsKey(ClaimConstants.ADDITIONAL_AZ_ATTR)) {
			requestParameters.put(ClaimConstants.ADDITIONAL_AZ_ATTR, JsonUtils.writeValueAsString(tokenMap.get(ClaimConstants.ADDITIONAL_AZ_ATTR)));
		}

		boolean foreignMode = (boolean) tokenMap.getOrDefault("foreignMode", false);

		// add authorization extension to determine whether token is a foreign token
		SAPAuthorizationExtension extension = new SAPAuthorizationExtension();
		extension.setForeignMode(foreignMode);
		HashMap<String, Serializable> extensionMap = new HashMap<>();
		extensionMap.put("sap", extension);
		clientAuthentication.setExtensions(extensionMap);
		clientAuthentication.setRequestParameters(Collections.unmodifiableMap(requestParameters));

		Authentication userAuthentication = getUserAuthentication(tokenMap, accessToken);

		clientAuthentication.setApproved(true);

		return new OAuth2Authentication(clientAuthentication.createOAuth2Request(), userAuthentication);
	}

	private Authentication getUserAuthentication(Map<String, Object> map, String accessToken) {
		return new XsuaaUserAuthenticationInfo(map, xsAppName, accessToken);
	}

	private Set<GrantedAuthority> getAuthorities(Collection<String> authorities) {
		Set<GrantedAuthority> result = new HashSet<GrantedAuthority>();
		for (String authority : authorities) {
			result.add(new SimpleGrantedAuthority(authority));
		}
		return result;
	}

	private boolean isStoreClaims() {
		return storeClaims;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.oauth2.provider.token.ResourceServerTokenServices#readAccessToken(java.lang.String)
	 */
	@Override
	public OAuth2AccessToken readAccessToken(String accessTokenValue) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}

	private AuthenticationHolder getCachedAuthentication(String accessToken) {
		logger.debug("Try to read Authentication for Token " + accessToken);
		ValueWrapper valueWrapper = tokenCache.get(accessToken);
		if (Objects.nonNull(valueWrapper)) {
			AuthenticationHolder auth = (AuthenticationHolder) valueWrapper.get();
			if (!auth.isExpired()) {
				return auth;
			} else {
				tokenCache.evict(accessToken);
			}
		}
		return null;
	}

	public AuthorizationMapper getAuthorizationMapper() {
		return authorizationMapper;
	}

	private class AuthenticationHolder {

		private final long expiration;
		private final OAuth2Authentication authentication;
		private final PostValidationAction postValidationAction;

		private AuthenticationHolder(OAuth2Authentication authentication, Long expiration, PostValidationAction postValidationAction) {
			super();

			Objects.nonNull(authentication);
			Objects.nonNull(expiration);

			this.authentication = authentication;
			this.expiration = expiration * 1000L;
			this.postValidationAction = postValidationAction;
		}

		public OAuth2Authentication getAuthentication() {
			return authentication;
		}

		public boolean isExpired() {
			return new Date(expiration).before(new Date());
		}

		public PostValidationAction getPostValidationAction() {
			return postValidationAction;
		}
	}

}
