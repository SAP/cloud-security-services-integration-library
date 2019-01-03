package com.sap.cloud.security.xsuaa.token;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;

import java.net.URI;
import java.util.*;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sap.xs2.security.container.XSTokenRequestImpl;
import com.sap.xsa.security.container.XSTokenRequest;

public class TokenImplTest {

	private Token token;
	private Jwt jwtSaml;
	private Jwt jwtCC;
	private Jwt jwtCCNoAttributes;
	private JWTClaimsSet.Builder claimsSetBuilder = null;
	private String xsAppName = "my-app-name!400";
	private String scopeRead = xsAppName + "." + "Display";
	private String scopeWrite = xsAppName + "." + "Edit";
	private String userName = "testUser";
	private String zoneId = "e2f7fbdb-0326-40e6-940f-dfddad057ff3";

	@Before
	public void setup() throws Exception {
		claimsSetBuilder = new JWTClaimsSet.Builder()
				.issueTime(new Date())
				.expirationTime(JwtGenerator.NO_EXPIRE)
				.claim(TokenImpl.CLAIM_USER_NAME, userName)
				.claim(TokenImpl.CLAIM_EMAIL, userName + "@test.org")
				.claim(TokenImpl.CLAIM_ZONE_ID, zoneId)
				.claim(TokenImpl.CLAIM_CLIENT_ID, "sb-java-hello-world")
				.claim(TokenImpl.CLAIM_ORIGIN, "userIdp")
				.claim(TokenImpl.CLAIM_GRANT_TYPE, TokenImpl.GRANTTYPE_SAML2BEARER);

		jwtSaml = JwtGenerator.createFromTemplate("/saml.txt");
		jwtCC = JwtGenerator.createFromFile("/token_cc.txt");
		jwtCCNoAttributes = JwtGenerator.createFromFile("/token_cc_noattr.txt");
	}

	@Test
	public void checkBasicJwtWithoutScopes() throws Exception {
		token = createToken(claimsSetBuilder);

		assertThat(token.getPassword(), nullValue());
		assertThat(token.getClientId(), is("sb-java-hello-world"));
		assertThat(token.getGrantType(), is(TokenImpl.GRANTTYPE_SAML2BEARER));
		assertThat(token.getOrigin(), is("userIdp"));
		assertThat(token.getLogonName(), is(userName));
		assertThat(token.getFamilyName(), nullValue());
		assertThat(token.getGivenName(), nullValue());
		assertThat(token.getEmail(), is("testUser@test.org"));
		assertThat(token.getSubaccountId(), is(zoneId));
		assertThat(token.isAccountNonLocked(), is(true));
		assertThat(token.isAccountNonExpired(), is(true));
		assertThat(token.getAuthorities().size(), is(0));
		assertThat(token.isEnabled(), is(false));
		assertThat(token.getAdditionalAuthAttribute("any"), nullValue());
	}

	@Test
	public void getAuthoritiesReturnsManyScopes() throws Exception {
		List<String> scopesList = new ArrayList<>();
		scopesList.add(scopeWrite);
		scopesList.add(scopeRead);
		claimsSetBuilder.claim("scope", scopesList);

		token = createToken(claimsSetBuilder);

		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) token.getAuthorities();
		assertThat(authorities.size(), is(2));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority(scopeRead)));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority(scopeWrite)));
	}

	@Test
	public void getZoneIdAsTenantGuid() throws Exception {
		claimsSetBuilder.claim(TokenImpl.CLAIM_ZONE_ID, zoneId);

		token = createToken(claimsSetBuilder);

		assertThat(token.getSubaccountId(), is(zoneId));
	}

	@Test
	public void getAuthoritiesNoScopeClaimReturnsEmptyList() throws Exception {
		claimsSetBuilder.claim(Token.CLAIM_SCOPES, new ArrayList<>());

		token = createToken(claimsSetBuilder);

		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) token.getAuthorities();
		assertThat(authorities.size(), is(0));
	}

	@Test
	public void isCredentialsExpiredWhenExpiryDateExceeded() throws Exception {
		claimsSetBuilder.issueTime(new Date(System.currentTimeMillis() - 300000));
		claimsSetBuilder.expirationTime(new Date(System.currentTimeMillis() - 20000));
		token = createToken(claimsSetBuilder);
		assertThat(token.isCredentialsNonExpired(), is(false));
	}

	@Test
	public void getUserNameIsUniqueWithOrigin() throws Exception {
		token = createToken(claimsSetBuilder);
		assertThat(token.getUsername(), is("user/userIdp/testUser"));
	}

	@Test
	public void toStringShouldReturnUserName() throws Exception {
		token = createToken(claimsSetBuilder);
		assertThat(token.toString(), is(token.getUsername()));
	}

	@Test(expected = IllegalArgumentException.class)
	public void getUserNameReturnsErrorWhenOriginContainsDelimeter() throws Exception {
		claimsSetBuilder.claim(TokenImpl.CLAIM_ORIGIN, "my/Idp");
		token = createToken(claimsSetBuilder);
		token.getUsername();
	}

	@Test
	public void getUniquePrincipalNameForOriginAndName() {
		String uniqueUserName = TokenImpl.getUniquePrincipalName("origin", "name");
		assertThat(uniqueUserName, is("user/origin/name"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void getUniquePrincipalNameRaisesErrorWhenOriginIsNull() {
		TokenImpl.getUniquePrincipalName(null, "name");
	}

	@Test(expected = IllegalArgumentException.class)
	public void getUniquePrincipalNameRaisesErrorWhenLogonNameIsNull() {
		TokenImpl.getUniquePrincipalName("origin", null);
	}

	@Test
	public void getPrincipalNameReturnUniqueLogonNameWithOrigin() {
		Token token = new TokenImpl(jwtSaml, xsAppName);
		UserDetails principal = token;
		Assert.assertEquals("user/useridp/Mustermann", principal.getUsername());
	}

	@Test
	public void getPrincipalNameReturnUniqueClientId() {
		Token token = new TokenImpl(jwtCC, xsAppName);
		Assert.assertEquals("sb-java-hello-world", token.getClientId());
		Assert.assertEquals("client/sb-java-hello-world", token.getUsername());
	}

	@Test
	public void getAuthoritiesReturnsAllScopes() throws Exception {
		Token token = new TokenImpl(jwtSaml, xsAppName);
		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) token.getAuthorities();
		assertThat(authorities.size(), is(4));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority("openid")));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority("java-hello-world.Delete")));
	}

	@Test
	public void getXsUserAttributeValues() throws Exception {
		Token token = new TokenImpl(jwtSaml, xsAppName);
		String[] userAttrValues = token.getXSUserAttribute("cost-center");
		assertThat(userAttrValues.length, is(2));
		assertThat(userAttrValues[0], is("0815"));
		assertThat(userAttrValues[1], is("4711"));
	}

	@Test
	public void getServiceInstanceIdFromExtAttr() throws Exception {
		claimsSetBuilder.claim(TokenImpl.CLAIM_EXTERNAL_ATTR, new SamlExternalAttrClaim());

		token = createToken(claimsSetBuilder);
		assertThat(token.getCloneServiceInstanceId(), is("abcd1234"));
	}

	@Test
	public void getSubdomainFromExtAttr() throws Exception {
		claimsSetBuilder.claim(TokenImpl.CLAIM_EXTERNAL_ATTR, new SamlExternalAttrClaim());

		token = createToken(claimsSetBuilder);
		assertThat(token.getSubdomain(), is("testsubdomain"));
	}

	@Test
	public void getSomeAdditionalAttributeValueFromAuthorizationAttr() throws Exception {
		claimsSetBuilder.claim(TokenImpl.CLAIM_ADDITIONAL_AZ_ATTR, new AdditionalAuthorizationAttrClaim());

		token = createToken(claimsSetBuilder);
		assertThat(token.getAdditionalAuthAttribute("external_group"), is("domain\\group1"));
	}

	@Test
	public void getAppToken() throws Exception {
		token = createToken(claimsSetBuilder);
		assertThat(token.getAppToken(), startsWith("eyJhbGciOiJSUzI1NiIsInR5"));
	}

	@Test
	public void requestClientCredentialsToken() throws Exception {
		// prepare response
		Map<String, String> ccToken = new HashMap<>();
		ccToken.put("access_token", "cc_token");

		// mock rest call
		// http://myuaa.com/oauth/token?grant_type=client_credentials&authorities=%7B%22az_attr%22:%7B%22a%22:%22b%22,%22c%22:%22d%22%7D%7D
		RestTemplate mockRestTemplate = Mockito.mock(RestTemplate.class);
		ResponseEntity<Map> response = new ResponseEntity<>(ccToken, HttpStatus.OK);
		Mockito.when(mockRestTemplate.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class))).thenReturn(response);

		token = createToken(claimsSetBuilder);

		String mockServerUrl = "http://myuaa.com";
		XSTokenRequestImpl tokenRequest = new XSTokenRequestImpl(mockServerUrl);
		tokenRequest.setRestTemplate(mockRestTemplate);
		tokenRequest.setClientId("c1").setClientSecret("s1").setType(XSTokenRequest.TYPE_CLIENT_CREDENTIALS_TOKEN);

		Map<String, String> azMape = new HashMap<>();
		azMape.put("a", "b");
		azMape.put("c", "d");
		tokenRequest.setAdditionalAuthorizationAttributes(azMape);

		assertThat(token.requestToken(tokenRequest), is("cc_token"));
	}

	private Token createToken(JWTClaimsSet.Builder claimsBuilder) throws Exception {
		Jwt jwt = JwtGenerator.createFromClaims(claimsBuilder.build());
		return new TokenImpl(jwt, xsAppName);
	}

	private static class SamlExternalAttrClaim {
		public String serviceinstanceid = "abcd1234";
		public String zdn = "testsubdomain";
	}

	private static class AdditionalAuthorizationAttrClaim {
		public String external_group = "domain\\group1";
		public String external_id = "ext-id-abcd1234";
	}
}
