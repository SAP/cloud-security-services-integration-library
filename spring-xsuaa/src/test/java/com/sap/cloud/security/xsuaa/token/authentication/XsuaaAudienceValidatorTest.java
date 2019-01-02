package com.sap.cloud.security.xsuaa.token.authentication;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.Token;

public class XsuaaAudienceValidatorTest {

	private Jwt tokenWithAudience;
	private Jwt tokenWithoutAudience;
	private XsuaaServiceConfiguration serviceConfigurationSameClientId;
	private XsuaaServiceConfiguration serviceConfigurationOtherGrantedClientId;
	private XsuaaServiceConfiguration serviceConfigurationUnGrantedClientId;
	private JWTClaimsSet.Builder claimsBuilder;

	@Before
	public void setup() throws Exception {
		serviceConfigurationSameClientId = new DummyXsuaaServiceConfiguration("sb-test1!t1", "test1!t1");
		serviceConfigurationOtherGrantedClientId = new DummyXsuaaServiceConfiguration("sb-test2!t1", "test2!t1");
		serviceConfigurationUnGrantedClientId = new DummyXsuaaServiceConfiguration("sb-test3!t1", "test3!t1");

		tokenWithAudience = JwtGenerator.createFromTemplate("/audience_1.txt");
		tokenWithoutAudience = JwtGenerator.createFromTemplate("/audience_2.txt");

		claimsBuilder = new JWTClaimsSet.Builder().issueTime(new Date()).expirationTime(JwtGenerator.NO_EXPIRE);
	}

	@Test
	public void testSameClientId() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationSameClientId).validate(tokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testSameClientIdWithoutAudience() {
		OAuth2TokenValidatorResult result2 = new XsuaaAudienceValidator(serviceConfigurationSameClientId).validate(tokenWithoutAudience);
		Assert.assertFalse(result2.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudience() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId).validate(tokenWithoutAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndDot() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(new DummyXsuaaServiceConfiguration("sb-test4!t1", "test4!t1")).validate(tokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientId() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationUnGrantedClientId).validate(tokenWithAudience);
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void testUnGrantedClientId() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationUnGrantedClientId).validate(tokenWithAudience);
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceButScopes() throws Exception {
		List<String> scopes = new ArrayList<String>();
		scopes.add("test2!t1.Display");
		claimsBuilder.claim(Token.CLAIM_SCOPES, scopes);

		Jwt tokenWithoutAudienceButScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId).validate(tokenWithoutAudienceButScopes);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndMatchingScopes() throws Exception {
		List<String> scopes = new ArrayList<String>();
		scopes.add("test3!t1.Display");
		claimsBuilder.claim(Token.CLAIM_SCOPES, scopes);

		Jwt tokenWithoutAudienceButScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId).validate(tokenWithoutAudienceButScopes);
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndScopes() throws Exception {
		Jwt tokenWithoutAudienceAndScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId).validate(tokenWithoutAudienceAndScopes);
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndEmptyScopes() throws Exception {
		claimsBuilder.claim(Token.CLAIM_SCOPES, "[]");
		Jwt tokenWithoutAudienceAndScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId).validate(tokenWithoutAudienceAndScopes);
		Assert.assertTrue(result.hasErrors());
	}

	class DummyXsuaaServiceConfiguration implements XsuaaServiceConfiguration {

		String clientId;
		String xsAppId;

		public DummyXsuaaServiceConfiguration(String clientId, String xsAppId) {
			this.clientId = clientId;
			this.xsAppId = xsAppId;
		}

		@Override
		public String getClientId() {
			return clientId;
		}

		@Override
		public String getClientSecret() {
			return null;
		}

		@Override
		public String getUaaUrl() {
			return null;
		}

		@Override
		public String getTokenKeyUrl(String zid, String subdomain) {
			return null;
		}

		@Override
		public String getAppId() {
			return xsAppId;
		}

		@Override
		public String getUaaDomain() {
			return null;
		}

	}
}
