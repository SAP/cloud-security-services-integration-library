package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;

/**
 * @deprecated OAuth2AuthenticationConverter won't be supported in future
 */
@Deprecated
public class OAuth2AuthenticationConverter extends TokenAuthenticationConverter {

	public OAuth2AuthenticationConverter(AuthoritiesExtractor authoritiesExtractor) {
		super(authoritiesExtractor);
	}

	@Override
	public BearerTokenAuthentication convert(Jwt jwt) {

		AuthenticationToken authenticationToken = (AuthenticationToken) super.convert(jwt);
		Objects.requireNonNull(authenticationToken, "OAuth2 Authentication token can't be null");
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(),
				jwt.getIssuedAt(), jwt.getExpiresAt());

		OAuth2AuthenticatedPrincipal authenticatedPrincipal = new OAuth2AuthenticatedPrincipal() {
			@Override
			public Map<String, Object> getAttributes() {
				return authenticationToken.getTokenAttributes();
			}

			@Override
			public Collection<? extends GrantedAuthority> getAuthorities() {
				return authenticationToken.getAuthorities();
			}

			@Override
			public String getName() {
				return authenticationToken.getName();
			}
		};

		return new BearerTokenAuthentication(authenticatedPrincipal, accessToken, authenticationToken.getAuthorities());
	}
}