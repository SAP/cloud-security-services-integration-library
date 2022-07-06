/**
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.comp;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.GrantType;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Copied from {@code com.sap.cloud.security.xsuaa.token.XsuaaTokenTest}.
 */
class XsuaaTokenCompTest {
	private static final String CLAIM_USER_NAME = "user_name";
	private com.sap.cloud.security.xsuaa.token.Token token;
	private Token tokenSAML;
	private String tokenCC;
	private JwtGenerator jwtGenerator = null;
	private final String userName = "testUser";
	private final String zoneId = "e2f7fbdb-0326-40e6-940f-dfddad057ff3";
	private static final String CLIENT_ID = "sb-java-hello-world";

	@BeforeEach
	void setup() throws IOException {
		jwtGenerator = JwtGenerator.getInstance(Service.XSUAA, CLIENT_ID)
				.withClaimValue(CLAIM_USER_NAME, userName)
				.withClaimValue(TokenClaims.EMAIL, userName + "@test.org")
				.withClaimValue(TokenClaims.XSUAA.ZONE_ID, zoneId)
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, CLIENT_ID)
				.withClaimValue(TokenClaims.XSUAA.ORIGIN, "userIdp")
				.withClaimValue(TokenClaims.AUTHORIZATION_PARTY, "client")
				.withClaimValue(TokenClaims.XSUAA.GRANT_TYPE, GrantType.JWT_BEARER.toString());

		tokenSAML = JwtGenerator.getInstanceFromFile(Service.XSUAA, "/saml.json").createToken();
		tokenCC = IOUtils.resourceToString("/token_cc.txt", UTF_8);
	}

	@Test
	void createInstance_failsForNonXsuaaToken() {
		Token iasToken = JwtGenerator.getInstance(Service.IAS, CLIENT_ID).createToken();
		assertThrows(IllegalArgumentException.class, () -> XsuaaTokenComp.createInstance(iasToken));
		assertThrows(IllegalArgumentException.class,
				() -> XsuaaTokenComp.createInstance(iasToken.getTokenValue()));
	}

	@Test
	void checkBasicJwtWithoutScopes() {
		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());

		assertThat(token.getClientId(), is("client"));
		assertThat(token.getGrantType(), is(GrantType.JWT_BEARER.toString()));
		assertThat(token.getOrigin(), is("userIdp"));
		assertThat(token.getFamilyName(), nullValue());
		assertThat(token.getGivenName(), nullValue());
		assertThat(token.getEmail(), is("testUser@test.org"));
		assertThat(token.getSubaccountId(), is(zoneId));
		// assertThat(token.getAuthorities().size(), is(0));
		assertThat(token.getExpirationDate(), is(Date.from(JwtGenerator.NO_EXPIRE_DATE)));
		assertThat(token.getExpiration(), is(JwtGenerator.NO_EXPIRE_DATE));
		assertThat(token.getAdditionalAuthAttribute("any"), nullValue());
		assertThat(token.getZoneId(), is(zoneId));
		assertThat(token.getLogonName(), is(userName));
	}

	@ParameterizedTest
	@MethodSource("clientIdTestArguments")
	void getClientId(String azp, List<String> aud, String expectedClientId) {
		token = XsuaaTokenComp.createInstance(jwtGenerator
				.withClaimValue(TokenClaims.AUTHORIZATION_PARTY, azp)
				.withClaimValues(TokenClaims.AUDIENCE, aud.toArray(new String[] {})).createToken());
		assertThat(token.getClientId(), is(expectedClientId));
	}

	private static Stream<Arguments> clientIdTestArguments() {
		return Stream.of(
				Arguments.of("azp", Arrays.asList("aud1", "aud2"), "azp"),
				Arguments.of("azp", Collections.singletonList("aud"), "azp"),
				Arguments.of("", Arrays.asList("aud1", "aud2"), CLIENT_ID),
				Arguments.of("", Collections.singletonList("aud"), "aud"),
				Arguments.of("", Collections.emptyList(), CLIENT_ID),
				Arguments.of(null, Collections.singletonList("aud"), "aud"),
				Arguments.of(null, Arrays.asList("aud1", "aud2"), CLIENT_ID),
				Arguments.of(null, Collections.emptyList(), CLIENT_ID),
				Arguments.of("   ", Collections.singletonList("aud"), "aud"),
				Arguments.of("   ", Arrays.asList("aud1", "aud2"), CLIENT_ID),
				Arguments.of("   ", Collections.emptyList(), CLIENT_ID));
	}

	@Test
	void getScopesReturnsAllScopes() {
		String xsAppName = "my-app-name!t400";
		String scopeRead = xsAppName + "." + "Read";
		String scopeWrite = xsAppName + "." + "Write";
		String scopeOther = "other-app-name!t777.Other";

		jwtGenerator.withClaimValues("scope", scopeWrite, scopeRead, scopeOther);

		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());

		Collection<String> scopes = token.getScopes();
		assertThat(scopes.size(), is(3));
		assertThat(scopes, hasItem(scopeRead));
		assertThat(scopes, hasItem(scopeWrite));
		assertThat(scopes, hasItem(scopeOther));
	}

	@Test
	void getZoneIdAsTenantGuid() {
		jwtGenerator.withClaimValue(TokenClaims.XSUAA.ZONE_ID, zoneId);

		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());

		assertThat(token.getSubaccountId(), is(zoneId));
		assertThat(token.getZoneId(), is(zoneId));
	}

	@Test
	void getSubaccountIdFromSystemAttributes() {
		assertThat(XsuaaTokenComp.createInstance(tokenSAML).getSubaccountId(), is("test-subaccount"));
	}

	@Test
	void getUserNameIsUniqueWithOrigin() {
		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());
		assertThat(token.getUsername(), is("user/userIdp/testUser"));
	}

	@Test
	void toStringShouldReturnUserName() {
		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());
		assertThat(token.toString(), is(token.getUsername()));
	}

	@Test
	void getUserNameReturnsErrorWhenOriginContainsDelimeter() {
		jwtGenerator.withClaimValue(TokenClaims.XSUAA.ORIGIN, "my/Idp");
		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());
		assertNull(token.getUsername());
	}

	@Test
	void getUniquePrincipalNameForOriginAndName() {
		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());
		assertThat(token.toString(), is("user/userIdp/testUser"));
	}

	@Test
	void getUniquePrincipalNameRaisesErrorWhenOriginIsNull() {
		jwtGenerator.withClaimValue(TokenClaims.XSUAA.ORIGIN, (String) null);
		assertNull(XsuaaTokenComp.createInstance(jwtGenerator.createToken()).toString());
	}

	@Test
	void getPrincipalNameReturnUniqueLogonNameWithOrigin() {
		assertEquals("user/useridp/Mustermann", XsuaaTokenComp.createInstance(tokenSAML).getUsername());
	}

	@Test
	void getPrincipalNameReturnUniqueClientId() {
		assertEquals("client/sb-java-hello-world", XsuaaTokenComp.createInstance(tokenCC).getUsername());
	}

	@Test
	void getXsUserAttributeValues() {
		String[] userAttrValues = XsuaaTokenComp.createInstance(tokenSAML).getXSUserAttribute("cost-center");
		assertThat(userAttrValues.length, is(2));
		assertThat(userAttrValues[0], is("0815"));
		assertThat(userAttrValues[1], is("4711"));
	}

	@Test
	void getXsUserAttributeValuesIsNull() {
		String[] userAttrValues = XsuaaTokenComp.createInstance(tokenSAML).getXSUserAttribute("costcenter");
		assertThat(userAttrValues, is(nullValue()));
	}

	@Test
	void getServiceInstanceIdFromExtAttr() {
		Map<String, String> extAttr = new HashMap<>();
		extAttr.put("serviceinstanceid", "abcd1234");
		extAttr.put("zdn", "testsubdomain");
		jwtGenerator.withClaimValue(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE, extAttr);

		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());
		assertThat(token.getCloneServiceInstanceId(), is("abcd1234"));
	}

	@Test
	void getSubdomainFromExtAttr() {
		Map<String, String> extAttr = new HashMap<>();
		extAttr.put("serviceinstanceid", "abcd1234");
		extAttr.put("zdn", "testsubdomain");
		jwtGenerator.withClaimValue(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE, extAttr);

		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());
		assertThat(token.getSubdomain(), is("testsubdomain"));
	}

	@Test
	void getSubdomainFails() {
		Map<String, String> addAuthAttr = new HashMap<>();
		addAuthAttr.put("external_group", "domain\\group1");
		addAuthAttr.put("external_id", "ext-id-abcd1234");
		assertThat(XsuaaTokenComp.createInstance(jwtGenerator.createToken()).getSubdomain(), nullValue());

		jwtGenerator.withClaimValue("az_attr", addAuthAttr);
		assertThat(XsuaaTokenComp.createInstance(jwtGenerator.createToken()).getSubdomain(), nullValue());
	}

	@Test
	void getAppToken() {
		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());
		assertThat(token.getAppToken(), startsWith("eyJqa3UiOiJodHRwOi8vbG9jYWx"));
	}

	@Test
	void unsupportedOperations() {
		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());

		assertThrows(UnsupportedOperationException.class, () -> token.getAuthorities());
		assertThrows(UnsupportedOperationException.class, () -> token.getPassword());
	}

	@Test
	void userDetailsOperations() {
		token = XsuaaTokenComp.createInstance(jwtGenerator.createToken());

		assertTrue(token.isAccountNonExpired());
		assertTrue(token.isAccountNonLocked());
		assertTrue(token.isCredentialsNonExpired());
		assertTrue(token.isEnabled());
	}

}