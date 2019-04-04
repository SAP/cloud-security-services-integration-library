package com.sap.cloud.security.xsuaa.token;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.test.JwtGenerator;

public class TokenAuthenticationConverterTest {
	private String xsAppName = "my-app-name!400";
	private TokenAuthenticationConverter tokenConverterDefault;
	private TokenAuthenticationConverter tokenConverterLocalScopesOnly;
	String scopeAdmin = xsAppName + "." + "Admin";
	String scopeRead = xsAppName + "." + "Read";
	String scopeOther = "other-app!234" + "." + "Other";

	@Before
	public void setup() {
		tokenConverterDefault = new TokenAuthenticationConverter(xsAppName);

		tokenConverterLocalScopesOnly = new TokenAuthenticationConverter(xsAppName);
		tokenConverterLocalScopesOnly.setLocalScopeAsAuthorities(true);
	}

	@Test
	public void extractAuthoritiesWithoutScopes() {
		Jwt jwt = new JwtGenerator().getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterDefault.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(0));
	}

	@Test
	public void extractAuthoritiesIgnoresForeignScopes() {
		Jwt jwt = new JwtGenerator().addScopes(scopeAdmin, scopeOther, scopeRead).getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterLocalScopesOnly.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(2));
		assertThat(authenticationToken.getAuthorities(), not(hasItem(new SimpleGrantedAuthority("Other"))));
	}

	@Test
	public void extractAuthoritiesWithScopes() {
		Jwt jwt = new JwtGenerator().addScopes(scopeAdmin, scopeRead, scopeOther).getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterDefault.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(3));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeRead)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeAdmin)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeOther)));
	}

	@Test
	public void extractCustomAuthoritiesWithScopes() {
		TokenAuthenticationConverter tokenConverterCustom = new MyTokenAuthenticationConverter(xsAppName, "cost-center",
				"country");

		Jwt jwt = new JwtGenerator()
				.addScopes(scopeAdmin)
				.addAttribute("cost-center", new String[] { "0815" })
				.addAttribute("country", new String[] { "DE", "IL" })
				.getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterCustom.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(4));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("ATTR:COST-CENTER=0815")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("ATTR:COUNTRY=DE")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("ATTR:COUNTRY=IL")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeAdmin)));
	}

	@Test
	public void authoritiesHaveLocalScopesWithoutAppIdPrefix() {
		String scopeWithNamespace = xsAppName + ".iot.Delete";
		String scopeWithOtherAppId = "anyAppId!200." + xsAppName + ".iot.Delete";

		Jwt jwt = new JwtGenerator()
				.addScopes(xsAppName + "." + scopeAdmin, scopeRead, scopeWithNamespace, scopeWithOtherAppId)
				.getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterLocalScopesOnly.convert(jwt);

		assertThat(authenticationToken.getAuthorities().size(), is(3));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeAdmin)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("iot.Delete")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("Read")));
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
