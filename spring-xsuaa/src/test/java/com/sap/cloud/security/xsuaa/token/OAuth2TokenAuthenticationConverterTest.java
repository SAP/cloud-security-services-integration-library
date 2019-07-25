package com.sap.cloud.security.xsuaa.token;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.sap.cloud.security.xsuaa.extractor.DefaultAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;

public class OAuth2TokenAuthenticationConverterTest {
	private String xsAppName = "my-app-name!400";
	private OAuth2AuthenticationConverter tokenConverterOauth2;
	String scopeAdmin = xsAppName + "." + "Admin";
	String scopeRead = xsAppName + "." + "Read";
	String scopeOther = "other-app!234" + "." + "Other";

	@Before
	public void setup() {
		tokenConverterOauth2 = new OAuth2AuthenticationConverter(new DefaultAuthoritiesExtractor());
	}

	@Test
	public void extractAuthoritiesWithScopesOAuth2Authentication() {
		Jwt jwt = new JwtGenerator().addScopes(scopeAdmin, scopeRead, scopeOther).getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterOauth2.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(3));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeRead)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeAdmin)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeOther)));

		assertTrue(authenticationToken instanceof OAuth2Authentication);
		assertThat(((OAuth2Authentication) authenticationToken).getOAuth2Request().getScope(), hasItem(scopeRead));
	}
}
