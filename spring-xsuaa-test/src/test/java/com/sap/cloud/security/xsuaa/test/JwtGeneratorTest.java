/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.xsuaa.test;

import static com.sap.cloud.security.xsuaa.test.TestConstants.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.startsWith;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import net.minidev.json.JSONArray;

public class JwtGeneratorTest {
	private JwtGenerator jwtGenerator;
	private static final String MY_CLIENT_ID = "client Id";
	private static final String MY_USER_NAME = "UserName";

	@Before
	public void setUp() throws Exception {
		jwtGenerator = new JwtGenerator(MY_CLIENT_ID);
	}

	@Test
	public void testBasicJwtToken() throws Exception {
		Jwt jwt = new JwtGenerator().getToken();
		assertThat(jwt.getClaimAsString("zid"), equalTo("uaa"));
		assertThat(jwt.getExpiresAt(), not(equals(nullValue())));
	}

	@Test
	public void testParameterizedJwtToken() throws Exception {
		jwtGenerator.setUserName(MY_USER_NAME);
		Jwt jwt = jwtGenerator.getToken();
		assertThat(jwt.getClaimAsString("client_id"), equalTo(MY_CLIENT_ID));
		assertThat(jwt.getClaimAsString("zid"), equalTo(JwtGenerator.IDENTITY_ZONE_ID));
		assertThat(jwt.getClaimAsString("user_name"), equalTo(MY_USER_NAME));
		assertThat(jwt.getClaimAsString("email"), startsWith(MY_USER_NAME));
		assertThat(jwt.getExpiresAt(), not(equals(nullValue())));
		assertThat(jwt.getTokenValue(), not(startsWith("Bearer ")));
	}

	@Test
	public void testBasicJwtTokenForHeader() throws Exception {
		String tokenForHeader = jwtGenerator.getTokenForAuthorizationHeader();
		assertThat(tokenForHeader, startsWith("Bearer "));
	}

	@Test
	public void testTokenWithScopes() throws Exception {
		Jwt jwt = jwtGenerator.addScopes(new String[] { DUMMY_SCOPE, ANOTHER_SCOPE }).getToken();
		assertThat(jwt.getClaimAsStringList("scope"), hasItems(DUMMY_SCOPE, ANOTHER_SCOPE));
	}

	@Test
	public void testTokenWithAttributes() throws Exception {
		Jwt jwt = jwtGenerator.addAttribute(DUMMY_ATTRIBUTE, new String[] { DUMMY_ATTRIBUTE }).addAttribute(ANOTHER_ATTRIBUTE, new String[] { ANOTHER_ATTRIBUTE_VALUE, ANOTHER_ATTRIBUTE_VALUE_2 }).getToken();
		Map<String, Object> attributes = jwt.getClaimAsMap("xs.user.attributes");
		assertThat((JSONArray) attributes.get(DUMMY_ATTRIBUTE), contains(DUMMY_ATTRIBUTE));
		assertThat((JSONArray) attributes.get(ANOTHER_ATTRIBUTE), contains(ANOTHER_ATTRIBUTE_VALUE, ANOTHER_ATTRIBUTE_VALUE_2));
	}

	@Test
	public void testTokenFromTemplateWithScopesAndAttributes() throws Exception {
		jwtGenerator.setUserName(MY_USER_NAME);
		Jwt jwt = jwtGenerator.createFromTemplate("/claims_template.txt");

		assertThat(jwt.getClaimAsString("client_id"), equalTo(MY_CLIENT_ID));
		assertThat(jwt.getClaimAsString("zid"), equalTo(JwtGenerator.IDENTITY_ZONE_ID));
		assertThat(jwt.getClaimAsString("user_name"), equalTo(MY_USER_NAME));
		assertThat(jwt.getClaimAsString("email"), startsWith(MY_USER_NAME));

		assertThat(jwt.getClaimAsStringList("scope"), hasItems("openid", "testScope", "testApp.localScope"));

		Map<String, Object> attributes = jwt.getClaimAsMap("xs.user.attributes");
		assertThat((JSONArray) attributes.get("usrAttr"), contains("value_1", "value_2"));
		jwt.getTokenValue();
	}

	@Test
	public void testTokenFromFile() throws Exception {
		Jwt jwtFromTemplate = jwtGenerator.createFromTemplate("/claims_template.txt");
		String jwtTokenFromTemplate = jwtFromTemplate.getTokenValue();
		Jwt jwtFromFile = JwtGenerator.createFromFile("/token_cc.txt");

		assertThat(jwtTokenFromTemplate, equalTo(jwtFromFile.getTokenValue()));
	}
}
