/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;

import java.util.Objects;

/**
 * @deprecated OAuth2AuthenticationConverter won't be supported in future
 * @see <a href="https://spring.io/projects/spring-security-oauth">Spring
 *      Security OAuth2 deprecation notice</a>
 * @see <a href=
 *      "https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth
 *      2.0 Migration Guide </a>
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

		return new BearerTokenAuthentication(new OAuth2Principal(authenticationToken), accessToken,
				authenticationToken.getAuthorities());
	}
}
