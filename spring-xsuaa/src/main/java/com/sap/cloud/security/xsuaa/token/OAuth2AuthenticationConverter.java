package com.sap.cloud.security.xsuaa.token;

import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;

/**
 * An authentication converter that sets a OAuth2Authentication object.
 * Required to keep compatibility with UAA.
 */
public class OAuth2AuthenticationConverter extends AbstractAuthenticationConverter {


	public OAuth2AuthenticationConverter(AuthoritiesExtractor authoritiesExtractor) {
		super(authoritiesExtractor);
	}

	@Override
	public OAuth2Authentication convert(Jwt jwt) {
		XsuaaToken token = new XsuaaToken(jwt);
		AuthorizationRequest authorizationRequest = new AuthorizationRequest(token.getClientId(),
				authoritiesExtractor.getAuthorities(token).stream()
						.map(object -> Objects.toString(object, null))
						.collect(Collectors.toList()));
		authorizationRequest.setApproved(true);
		authorizationRequest.setAuthorities(authoritiesExtractor.getAuthorities(token));

		return new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
				new AuthenticationToken(jwt, authoritiesExtractor.getAuthorities(new XsuaaToken(jwt))));
	}
}