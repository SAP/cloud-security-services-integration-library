/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.extractor.DefaultAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OAuth2TokenAuthenticationConverterTest {
	private static final String XS_APP_NAME = "my-app-name!400";
	private static AbstractAuthenticationToken authenticationToken;
	String scopeAdmin = XS_APP_NAME + "." + "Admin";
	String scopeRead = XS_APP_NAME + "." + "Read";
	String scopeOther = "other-app!234" + "." + "Other";

	@Before
	public void setup() {
		OAuth2AuthenticationConverter tokenConverterOauth2 = new OAuth2AuthenticationConverter(
				new DefaultAuthoritiesExtractor());
		Jwt jwt = new JwtGenerator().addScopes(scopeAdmin, scopeRead, scopeOther).getToken();
		authenticationToken = tokenConverterOauth2.convert(jwt);
	}

	@Test
	public void extractAuthoritiesWithScopesOAuth2Authentication() {
		assertThat(authenticationToken.getAuthorities().size(), is(3));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeRead)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeAdmin)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeOther)));
		assertTrue(authenticationToken instanceof BearerTokenAuthentication);
	}

	@Test
	public void extractPrincipalInfoTest() {
		OAuth2Principal principal = (OAuth2Principal) authenticationToken.getPrincipal();
		assertThat(principal.getName(), endsWith("testuser"));
		assertThat(principal.getHeaders(), notNullValue());
		assertThat(principal.getScopes(), notNullValue());
		assertTrue(principal.getScopes().contains(scopeAdmin));
		assertEquals("sb-xsapplication!t895", principal.getClaim(TokenClaims.CLAIM_AUTHORIZATION_PARTY));
	}
}
