/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.xsuaa.token;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jwt.JWTClaimsSet;

public class TokenAuthenticationConverterTest {
	private JWTClaimsSet.Builder claimsSetBuilder = null;
	private String xsAppName = "my-app-name!400";
	private TokenAuthenticationConverter tokenConverter;
	String scopeAdmin = xsAppName + "." + "Admin";
	String scopeRead = xsAppName + "." + "Read";
	private Jwt jwtSamlWithXsUserAttributes;

	@Before
	public void setup() throws Exception {
		claimsSetBuilder = new JWTClaimsSet.Builder().issueTime(new Date()).expirationTime(JwtGenerator.NO_EXPIRE);
		tokenConverter = new TokenAuthenticationConverter(xsAppName);
		jwtSamlWithXsUserAttributes = JwtGenerator.createFromTemplate("/saml.txt");
	}

	@Test
	public void extractAuthoritiesWithoutScopes() throws Exception {
		Jwt jwt = JwtGenerator.createFromClaims(claimsSetBuilder.build());

		AbstractAuthenticationToken authenticationToken = tokenConverter.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(0));
	}

	@Test
	public void extractAuthoritiesWithScopes() throws Exception {
		List<String> scopesList = new ArrayList<>();
		scopesList.add(scopeAdmin);
		scopesList.add(scopeRead);
		claimsSetBuilder.claim(Token.CLAIM_SCOPES, scopesList);
		Jwt jwt = JwtGenerator.createFromClaims(claimsSetBuilder.build());

		AbstractAuthenticationToken authenticationToken = tokenConverter.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(2));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeRead)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeAdmin)));
	}

	@Test
	public void extractCustomAuthoritiesWithScopes() throws Exception {
		tokenConverter = new MyTokenAuthenticationConverter(xsAppName, "cost-center", "country");

		AbstractAuthenticationToken authenticationToken = tokenConverter.convert(jwtSamlWithXsUserAttributes);
		assertThat(authenticationToken.getAuthorities().size(), is(7));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("ATTR:COST-CENTER=0815")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("ATTR:COST-CENTER=4711")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("ATTR:COUNTRY=Germany")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("java-hello-world.Delete")));
	}

	private static class MyTokenAuthenticationConverter extends TokenAuthenticationConverter {

		protected String[] xsUserAttributes;

		public MyTokenAuthenticationConverter(String appId, String... xsUserAttributes) {
			super(appId);
			this.xsUserAttributes = xsUserAttributes;
		}

		@Override
		protected Collection<String> getCustomAuthorities(Token token) {
			Set<String> newAuthorities = new HashSet<>();
			for (String attribute : xsUserAttributes) {
				String[] xsUserAttributeValues = token.getXSUserAttribute(attribute);
				if (xsUserAttributeValues != null) {
					for (String xsUserAttributeValue : xsUserAttributeValues) {
						newAuthorities.add(getSidForAttributeValue(attribute, xsUserAttributeValue));
					}
				}
			}
			return newAuthorities;
		}

		public static String getSidForAttributeValue(String attributeName, String attributeValue) {
			return "ATTR:" + attributeName.toUpperCase() + "=" + attributeValue;
		}
	}
}
