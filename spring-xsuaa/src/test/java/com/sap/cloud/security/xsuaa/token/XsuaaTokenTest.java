/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

import com.sap.cloud.security.token.InvalidTokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;

public class XsuaaTokenTest {

	private XsuaaToken token;
	private Jwt jwtSaml;
	private Jwt jwtCC;
	private JWTClaimsSet.Builder claimsSetBuilder = null;
	private String xsAppName = "my-app-name!t400";
	private String scopeRead = xsAppName + "." + "Read";
	private String scopeWrite = xsAppName + "." + "Write";
	private String scopeOther = "other-app-name!t777.Other";
	private String userName = "testUser";
	private String zoneId = "e2f7fbdb-0326-40e6-940f-dfddad057ff3";
	private static final String CLIENT_ID = "sb-java-hello-world";

	@BeforeEach
	public void setup() throws IOException {
		claimsSetBuilder = new JWTClaimsSet.Builder()
				.issueTime(new Date())
				.expirationTime(JwtGenerator.NO_EXPIRE_DATE)
				.claim(TokenClaims.CLAIM_USER_NAME, userName).claim(TokenClaims.CLAIM_EMAIL, userName + "@test.org")
				.claim(TokenClaims.CLAIM_ZONE_ID, zoneId).claim(TokenClaims.CLAIM_CLIENT_ID, CLIENT_ID)
				.claim(TokenClaims.CLAIM_ORIGIN, "userIdp")
				.claim(TokenClaims.CLAIM_AUTHORIZATION_PARTY, "client")
				.claim(TokenClaims.CLAIM_GRANT_TYPE, XsuaaToken.GRANTTYPE_SAML2BEARER);

		jwtSaml = new JwtGenerator().createFromTemplate("/saml.txt");
		jwtCC = JwtGenerator.createFromFile("/token_cc.txt");
	}

	@Test
	public void checkBasicJwtWithoutScopes() {
		token = createToken(claimsSetBuilder);

		assertThat(token.getPassword(), nullValue());
		assertThat(token.getClientId(), is("client"));
		assertThat(token.getGrantType(), is(XsuaaToken.GRANTTYPE_SAML2BEARER));
		assertThat(token.getOrigin(), is("userIdp"));
		assertThat(token.getLogonName(), is(userName));
		assertThat(token.getFamilyName(), nullValue());
		assertThat(token.getGivenName(), nullValue());
		assertThat(token.getEmail(), is("testUser@test.org"));
		assertThat(token.getZoneId(), is(zoneId));
		assertThat(token.getSubaccountId(), is(zoneId));
		assertThat(token.isAccountNonLocked(), is(true));
		assertThat(token.isAccountNonExpired(), is(true));
		assertThat(token.getAuthorities().size(), is(0));
		assertThat(token.isEnabled(), is(false));
		assertThat(token.getExpirationDate(), is(JwtGenerator.NO_EXPIRE_DATE));
		assertThat(token.getExpiration(), is(JwtGenerator.NO_EXPIRE_DATE.toInstant()));
		assertThat(token.getAdditionalAuthAttribute("any"), nullValue());
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "  " })
	public void getClientIdNegativeTest(String cid) {
		token = createToken(
				claimsSetBuilder.claim(TokenClaims.CLAIM_AUTHORIZATION_PARTY, null).audience(Collections.EMPTY_LIST)
						.claim(TokenClaims.CLAIM_CLIENT_ID, cid));
		assertThatThrownBy(() -> token.getClientId()).isExactlyInstanceOf(InvalidTokenException.class);
	}

	@ParameterizedTest
	@MethodSource("clientIdTestArguments")
	public void getClientIdTest(String azp, List<String> aud, String expectedClientId) {
		token = createToken(claimsSetBuilder.claim(TokenClaims.CLAIM_AUTHORIZATION_PARTY, azp).audience(aud));
		assertThat(token.getClientId(), is(expectedClientId));
	}

	private static Stream<Arguments> clientIdTestArguments() {
		return Stream.of(
				Arguments.of("azp", Arrays.asList("aud1", "aud2"), "azp"),
				Arguments.of("azp", Arrays.asList("aud"), "azp"),
				Arguments.of("", Arrays.asList("aud1", "aud2"), CLIENT_ID),
				Arguments.of("", Arrays.asList("aud"), "aud"),
				Arguments.of("", Arrays.asList(), CLIENT_ID),
				Arguments.of(null, Arrays.asList("aud"), "aud"),
				Arguments.of(null, Arrays.asList("aud1", "aud2"), CLIENT_ID),
				Arguments.of(null, Arrays.asList(), CLIENT_ID),
				Arguments.of("   ", Arrays.asList("aud"), "aud"),
				Arguments.of("   ", Arrays.asList("aud1", "aud2"), CLIENT_ID),
				Arguments.of("   ", Arrays.asList(), CLIENT_ID));
	}

	@Test
	public void authenticationConverterShouldSetAuthorities() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsAppName);
		converter.setLocalScopeAsAuthorities(true);

		List<String> scopesList = new ArrayList<>();
		scopesList.add(scopeWrite);
		scopesList.add(scopeRead);
		scopesList.add(scopeOther);
		claimsSetBuilder.claim("scope", scopesList);

		Jwt jwt = JwtGenerator.createFromClaims(claimsSetBuilder.build());

		AuthenticationToken authToken = (AuthenticationToken) converter.convert(jwt);
		token = (XsuaaToken) authToken.getPrincipal();

		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) token.getAuthorities();
		assertThat(authorities.size(), is(2));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority("Read")));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority("Write")));
	}

	@Test
	public void getAuthoritiesReturnsSetAuthorities() {
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new SimpleGrantedAuthority(scopeRead));
		authorities.add(new SimpleGrantedAuthority(scopeOther));

		XsuaaToken token = new XsuaaToken(jwtSaml);
		token.setAuthorities(authorities);

		Collection<GrantedAuthority> actAuthorities = (Collection<GrantedAuthority>) token.getAuthorities();
		assertThat(actAuthorities.size(), is(2));
		assertThat(actAuthorities, hasItem(new SimpleGrantedAuthority(scopeOther)));
	}

	@Test
	public void getScopesReturnsAllScopes() {
		List<String> scopesList = new ArrayList<>();
		scopesList.add(scopeWrite);
		scopesList.add(scopeRead);
		scopesList.add(scopeOther);
		claimsSetBuilder.claim("scope", scopesList);

		token = createToken(claimsSetBuilder);

		Collection<String> scopes = token.getScopes();
		assertThat(scopes.size(), is(3));
		assertThat(scopes, hasItem(scopeRead));
		assertThat(scopes, hasItem(scopeWrite));
		assertThat(scopes, hasItem(scopeOther));
	}

	@Test
	public void getZoneIdAsTenantGuid() {
		claimsSetBuilder.claim(TokenClaims.CLAIM_ZONE_ID, zoneId);

		token = createToken(claimsSetBuilder);

		assertThat(token.getSubaccountId(), is(zoneId));
		assertThat(token.getZoneId(), is(zoneId));
	}

	@Test
	public void getSubaccountIdFromSystemAttributes() {
		Token token = new XsuaaToken(jwtSaml);
		assertThat(token.getSubaccountId(), is("test-subaccount"));
	}

	@Test
	public void getAuthoritiesNoScopeClaimReturnsEmptyList() {
		claimsSetBuilder.claim(TokenClaims.CLAIM_SCOPES, new ArrayList<>());

		token = createToken(claimsSetBuilder);

		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) token.getAuthorities();
		assertThat(authorities.size(), is(0));
	}

	@Test
	public void isCredentialsExpiredWhenExpiryDateExceeded() {
		claimsSetBuilder.issueTime(new Date(System.currentTimeMillis() - 300000));
		claimsSetBuilder.expirationTime(new Date(System.currentTimeMillis() - 20000));
		token = createToken(claimsSetBuilder);
		assertThat(token.isCredentialsNonExpired(), is(false));
	}

	@Test
	public void getUserNameIsUniqueWithOrigin() {
		token = createToken(claimsSetBuilder);
		assertThat(token.getUsername(), is("user/userIdp/testUser"));
	}

	@Test
	public void toStringShouldReturnUserName() {
		token = createToken(claimsSetBuilder);
		assertThat(token.toString(), is(token.getUsername()));
	}

	@Test
	public void getUserNameReturnsErrorWhenOriginContainsDelimeter() {
		claimsSetBuilder.claim(TokenClaims.CLAIM_ORIGIN, "my/Idp");
		token = createToken(claimsSetBuilder);
		assertNull(token.getUsername());
	}

	@Test
	public void getUniquePrincipalNameForOriginAndName() {
		String uniqueUserName = XsuaaToken.getUniquePrincipalName("origin", "name");
		assertThat(uniqueUserName, is("user/origin/name"));
	}

	@Test
	public void getUniquePrincipalNameRaisesErrorWhenOriginIsNull() {
		assertNull(XsuaaToken.getUniquePrincipalName(null, "name"));
	}

	@Test
	public void getUniquePrincipalNameRaisesErrorWhenLogonNameIsNull() {
		assertNull(XsuaaToken.getUniquePrincipalName("origin", null));
	}

	@Test
	public void getPrincipalNameReturnUniqueLogonNameWithOrigin() {
		Token token = new XsuaaToken(jwtSaml);
		UserDetails principal = token;
		assertEquals("user/useridp/Mustermann", principal.getUsername());
	}

	@Test
	public void getPrincipalNameReturnUniqueClientId() {
		Token token = new XsuaaToken(jwtCC);
		assertEquals(CLIENT_ID, token.getClientId());
		assertEquals("client/sb-java-hello-world", token.getUsername());
	}

	@Test
	public void getXsUserAttributeValues() {
		Token token = new XsuaaToken(jwtSaml);
		String[] userAttrValuesCostCenter = token.getXSUserAttribute("cost-center");
		String[] userAttrValuesCountry = token.getXSUserAttribute("country");
		assertThat(userAttrValuesCountry.length, is(1));
		assertThat(userAttrValuesCostCenter.length, is(2));
		assertThat(userAttrValuesCostCenter[0], is("0815"));
		assertThat(userAttrValuesCostCenter[1], is("4711"));
	}

	@Test
	public void getXsUserAttributeValuesIsNull() {
		Token token = new XsuaaToken(jwtSaml);
		String[] userAttrValues = token.getXSUserAttribute("costcenter");
		assertThat(userAttrValues, is(nullValue()));
	}

	@Test
	public void getServiceInstanceIdFromExtAttr() {
		claimsSetBuilder.claim(XsuaaToken.CLAIM_EXTERNAL_ATTR, new SamlExternalAttrClaim());

		token = createToken(claimsSetBuilder);
		assertThat(token.getCloneServiceInstanceId(), is("abcd1234"));
	}

	@Test
	public void getSubdomainFromExtAttr() {
		claimsSetBuilder.claim(XsuaaToken.CLAIM_EXTERNAL_ATTR, new SamlExternalAttrClaim());

		token = createToken(claimsSetBuilder);
		assertThat(token.getSubdomain(), is("testsubdomain"));
	}

	@Test
	public void getSubdomainFails() {
		assertThat(createToken(claimsSetBuilder).getSubdomain(), nullValue());

		claimsSetBuilder.claim(XsuaaToken.CLAIM_EXTERNAL_ATTR, new AdditionalAuthorizationAttrClaim());
		assertThat(createToken(claimsSetBuilder).getSubdomain(), nullValue());
	}

	@Test
	public void getSomeAdditionalAttributeValueFromAuthorizationAttr() {
		claimsSetBuilder.claim(XsuaaToken.CLAIM_ADDITIONAL_AZ_ATTR, new AdditionalAuthorizationAttrClaim());

		token = createToken(claimsSetBuilder);
		assertThat(token.getAdditionalAuthAttribute("external_group"), is("domain\\group1"));
	}

	@Test
	public void getAppToken() {
		token = createToken(claimsSetBuilder);
		assertThat(token.getAppToken(), startsWith("eyJhbGciOiJSUzI1NiIsInR5"));
	}

	private XsuaaToken createToken(JWTClaimsSet.Builder claimsBuilder) {
		Jwt jwt = JwtGenerator.createFromClaims(claimsBuilder.build());
		return new XsuaaToken(jwt);
	}

	public static class SamlExternalAttrClaim {
		public String serviceinstanceid = "abcd1234";
		public String zdn = "testsubdomain";
	}

	public static class AdditionalAuthorizationAttrClaim {
		public String external_group = "domain\\group1";
		public String external_id = "ext-id-abcd1234";
	}
}
