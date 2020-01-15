package com.sap.bulletinboard.ads.services;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class SAPOfflineTokenServicesCloud implements ResourceServerTokenServices, InitializingBean {

	private CombiningValidator<Token> tokenValidator;
	private OAuth2ServiceConfiguration serviceConfiguration;

	public SAPOfflineTokenServicesCloud(OAuth2ServiceConfiguration serviceConfiguration) {
		this.serviceConfiguration = serviceConfiguration;
	}

	@Override
	public OAuth2Authentication loadAuthentication(String accessToken)
			throws AuthenticationException, InvalidTokenException {
		XsuaaToken token = new XsuaaToken(accessToken);
		Set<String> scopes = token.getScopes().stream().collect(Collectors.toSet());

		AuthorizationRequest authorizationRequest = new AuthorizationRequest(new HashMap<>(), null,
				serviceConfiguration.getClientId(), scopes, new HashSet<>(), null,
				tokenValidator.validate(token).isValid(), "", "", null);

		return new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);
	}

	@Override
	public void afterPropertiesSet() {
		tokenValidator = JwtValidatorBuilder.getInstance(serviceConfiguration).build();
	}

	@Override public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}
}