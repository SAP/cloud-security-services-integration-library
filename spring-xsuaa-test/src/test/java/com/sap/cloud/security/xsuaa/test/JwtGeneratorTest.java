package com.sap.cloud.security.xsuaa.test;

import static com.sap.cloud.security.xsuaa.test.TestConstants.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.isEmptyString;
import static org.hamcrest.Matchers.startsWith;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import net.minidev.json.JSONArray;

public class JwtGeneratorTest {
	private JwtGenerator jwtGenerator;
	private static final String MY_CLIENT_ID = "sb-clientId!20";
	private static final String MY_USER_NAME = "UserName";
	private static final String MY_SUBDOMAIN = "my-subaccount-subdomain";

	@Before
	public void setUp() {
		jwtGenerator = new JwtGenerator(MY_CLIENT_ID, MY_SUBDOMAIN);
	}

	@Test
	public void testBasicJwtToken() {
		Jwt jwt = new JwtGenerator().deriveAudiences(true).getToken();
		assertThat(jwt.getClaimAsString("zid"), equalTo(JwtGenerator.DEFAULT_IDENTITY_ZONE_ID));
		assertThat(jwt.getExpiresAt(), not(equals(nullValue())));
		assertThat(jwt.getAudience(), is(nullValue()));
		assertThat(getExternalAttributeFromClaim(jwt, "zdn"), isEmptyString());
	}

	@Test
	public void testParameterizedJwtToken() {
		jwtGenerator.setUserName(MY_USER_NAME);
		Jwt jwt = jwtGenerator.getToken();
		assertThat(jwt.getClaimAsString(JwtGenerator.TokenClaims.CLAIM_CLIENT_ID), equalTo(MY_CLIENT_ID));
		assertThat(jwt.getClaimAsString(JwtGenerator.TokenClaims.CLAIM_ZONE_ID), startsWith(MY_SUBDOMAIN));
		assertThat(jwt.getClaimAsString(JwtGenerator.TokenClaims.CLAIM_USER_NAME), equalTo(MY_USER_NAME));
		assertThat(jwt.getClaimAsString(JwtGenerator.TokenClaims.CLAIM_EMAIL), startsWith(MY_USER_NAME));
		assertThat(getExternalAttributeFromClaim(jwt, "zdn"), equalTo(MY_SUBDOMAIN));
		assertThat(jwt.getExpiresAt(), not(equals(nullValue())));
		assertThat(jwt.getTokenValue(), not(startsWith("Bearer ")));
	}

	@Test
	public void testBasicJwtTokenForHeader() {
		String tokenForHeader = jwtGenerator.getTokenForAuthorizationHeader();
		assertThat(tokenForHeader, startsWith("Bearer "));
	}

	@Test
	public void testTokenWithScopes() {
		Jwt jwt = jwtGenerator.addScopes(new String[] { DUMMY_SCOPE, ANOTHER_SCOPE }).getToken();
		assertThat(jwt.getClaimAsStringList("scope"), hasItems(DUMMY_SCOPE, ANOTHER_SCOPE));
	}

	@Test
	public void testTokenWithAttributes() {
		Jwt jwt = jwtGenerator.addAttribute(DUMMY_ATTRIBUTE, new String[] { DUMMY_ATTRIBUTE })
				.addAttribute(ANOTHER_ATTRIBUTE, new String[] { ANOTHER_ATTRIBUTE_VALUE, ANOTHER_ATTRIBUTE_VALUE_2 })
				.getToken();
		Map<String, Object> attributes = jwt.getClaimAsMap("xs.user.attributes");
		assertThat((JSONArray) attributes.get(DUMMY_ATTRIBUTE), contains(DUMMY_ATTRIBUTE));
		assertThat((JSONArray) attributes.get(ANOTHER_ATTRIBUTE),
				contains(ANOTHER_ATTRIBUTE_VALUE, ANOTHER_ATTRIBUTE_VALUE_2));
	}

	@Test
	public void testTokenWithKeyId() {
		Jwt jwt = jwtGenerator.setJwtHeaderKeyId("keyIdValue").getToken();
		assertThat(jwt.getHeaders().containsKey("kid"), is(true));
		assertThat(jwt.getHeaders().get("kid"), is("keyIdValue"));
	}

	@Test
	public void testTokenFromTemplateWithScopesAndAttributes() throws IOException {
		jwtGenerator.setUserName(MY_USER_NAME);
		Jwt jwt = jwtGenerator.createFromTemplate("/claims_template.txt");

		assertThat(jwt.getClaimAsString("client_id"), equalTo(MY_CLIENT_ID));
		assertThat(jwt.getClaimAsString("zid"), startsWith(MY_SUBDOMAIN));
		assertThat(jwt.getClaimAsString("user_name"), equalTo(MY_USER_NAME));
		assertThat(jwt.getClaimAsString("email"), startsWith(MY_USER_NAME));
		assertThat(getExternalAttributeFromClaim(jwt, "zdn"), equalTo(MY_SUBDOMAIN));

		assertThat(jwt.getClaimAsStringList("scope"), hasItems("openid", "testScope", "testApp.localScope"));

		Map<String, Object> attributes = jwt.getClaimAsMap("xs.user.attributes");
		assertThat((JSONArray) attributes.get("usrAttr"), contains("value_1", "value_2"));
		jwt.getTokenValue();
	}

	@Test
	public void testTokenFromFile() throws IOException {
		Jwt jwtFromTemplate = jwtGenerator.createFromTemplate("/claims_template.txt");
		String jwtTokenFromTemplate = jwtFromTemplate.getTokenValue();
		Jwt jwtFromFile = JwtGenerator.createFromFile("/token_cc.txt");

		assertThat(jwtTokenFromTemplate, equalTo(jwtFromFile.getTokenValue()));
	}

	@Test
	public void testTokenWithCustomClaims() {
		Map<String, Object> claims = new HashMap<>();
		claims.put("myCustomClaim", "myCustomClaimValue");
		Jwt jwt = jwtGenerator.addCustomClaims(claims).getToken();

		assertThat(jwt.getClaimAsString("myCustomClaim"), equalTo("myCustomClaimValue"));
	}

	@Test
	public void testTokenWithDerivedAudienceClaim() {

		Jwt jwt = jwtGenerator.addScopes("openid", "app1.scope", "app2.sub.scope", "app2.scope", ".scopeWithoutAppId")
				.deriveAudiences(true)
				.getToken();

		assertThat(jwt.getAudience().size(), equalTo(2));
		assertThat(jwt.getAudience(), hasItem("app1"));
		assertThat(jwt.getAudience(), hasItem("app2"));
	}

	private String getExternalAttributeFromClaim(Jwt jwt, String attributeName) {
		Map<String, Object> externalAttribute = jwt.getClaimAsMap("ext_attr");
		return externalAttribute == null ? null : (String) externalAttribute.get(attributeName);
	}
}
