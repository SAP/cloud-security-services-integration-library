package com.sap.cloud.security.xsuaa.token;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_CLIENT_ID;

import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;

/**
 * An authentication converter that sets a OAuth2Authentication object. Required
 * to keep compatibility with UAA.
 */
public class OAuth2AuthenticationConverter extends TokenAuthenticationConverter {

	public OAuth2AuthenticationConverter(AuthoritiesExtractor authoritiesExtractor) {
		super(authoritiesExtractor);
	}

	@Override
	public OAuth2Authentication convert(Jwt jwt) {
		AuthenticationToken authenticationToken = (AuthenticationToken) super.convert(jwt);
		String clientId = jwt.getClaimAsString(CLAIM_CLIENT_ID);
		AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId,
				authenticationToken.getAuthorities().stream().map(Objects::toString).collect(Collectors.toList()));
		authorizationRequest.setApproved(true);
		authorizationRequest.setAuthorities(authenticationToken.getAuthorities());

		return new OAuth2Authentication(authorizationRequest.createOAuth2Request(), authenticationToken);
	}
}