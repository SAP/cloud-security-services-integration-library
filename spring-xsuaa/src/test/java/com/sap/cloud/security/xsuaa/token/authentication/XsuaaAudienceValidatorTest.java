package com.sap.cloud.security.xsuaa.token.authentication;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;

import java.io.IOException;
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
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.Token;

public class XsuaaAudienceValidatorTest {

	private Jwt tokenWithAudience;
	private Jwt tokenWithoutAudience;
	private Jwt cloneTokenWithoutAudience;
	private Jwt cloneTokenWithAudience;

	private XsuaaServiceConfiguration serviceConfigurationSameClientId;
	private XsuaaServiceConfiguration serviceConfigurationOtherGrantedClientId;
	private XsuaaServiceConfiguration serviceConfigurationUnGrantedClientId;
	private XsuaaServiceConfiguration serviceConfigurationBrokerPlan;

	private JWTClaimsSet.Builder claimsBuilder;

	@Before
	public void setup() throws IOException {
		serviceConfigurationSameClientId = new DummyXsuaaServiceConfiguration("sb-test1!t1", "test1!t1");
		serviceConfigurationOtherGrantedClientId = new DummyXsuaaServiceConfiguration("sb-test2!t1", "test2!t1");
		serviceConfigurationUnGrantedClientId = new DummyXsuaaServiceConfiguration("sb-test3!t1", "test3!t1");
		serviceConfigurationBrokerPlan = new DummyXsuaaServiceConfiguration("sb-test3!b1", "test3!b1");
		tokenWithAudience = new JwtGenerator().createFromTemplate("/audience_1.txt");
		tokenWithoutAudience = new JwtGenerator().createFromTemplate("/audience_2.txt");
		cloneTokenWithAudience = new JwtGenerator().createFromTemplate("/audience_3.txt");
		cloneTokenWithoutAudience = new JwtGenerator().createFromTemplate("/audience_4.txt");

		claimsBuilder = new JWTClaimsSet.Builder().issueTime(new Date()).expirationTime(JwtGenerator.NO_EXPIRE_DATE);
		claimsBuilder.claim(Token.CLIENT_ID, "sb-test1!t1");
	}

	@Test
	public void testSameClientId() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationSameClientId)
				.validate(tokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testSameClientIdWithoutAudience() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationSameClientId)
				.validate(tokenWithoutAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testExtractAudiencesFromTokenScopes() {
		Jwt token = new JwtGenerator().addScopes("test1!t1.read","test2!t1.read","test2!t1.write", ".scopeWithoutAppId").getToken();
		List<String> audiences = new XsuaaAudienceValidator(serviceConfigurationSameClientId).getAllowedAudiences(token);
		Assert.assertThat(audiences.size(), is(2));
		Assert.assertThat(audiences, hasItem("test1!t1"));
		Assert.assertThat(audiences, hasItem("test2!t1"));
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudience() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndDot() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(
				new DummyXsuaaServiceConfiguration("sb-test4!t1", "test4!t1")).validate(tokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientId() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationUnGrantedClientId)
				.validate(tokenWithAudience);
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void testUnGrantedClientId() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationUnGrantedClientId)
				.validate(tokenWithAudience);
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceButScopes() {
		List<String> scopes = new ArrayList<String>();
		scopes.add("test2!t1.Display");
		claimsBuilder.claim(Token.CLAIM_SCOPES, scopes);

		Jwt tokenWithoutAudienceButScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudienceButScopes);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndMatchingScopes() {
		List<String> scopes = new ArrayList<String>();
		scopes.add("test3!t1.Display");
		claimsBuilder.claim(Token.CLAIM_SCOPES, scopes);

		Jwt tokenWithoutAudienceButScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudienceButScopes);
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndScopes() {
		Jwt tokenWithoutAudienceAndScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudienceAndScopes);
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndEmptyScopes() {
		claimsBuilder.claim(Token.CLAIM_SCOPES, "[]");
		Jwt tokenWithoutAudienceAndScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudienceAndScopes);
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void testBrokerCloneWithAudience() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationBrokerPlan)
				.validate(cloneTokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testBrokerCloneWithAudience_new() {
		OAuth2TokenValidatorResult result = new XsuaaCloneTokenValidator(serviceConfigurationBrokerPlan.getClientId(), serviceConfigurationBrokerPlan.getAppId())
				.validate(cloneTokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testBrokerCloneWithoutAudience() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationBrokerPlan)
				.validate(cloneTokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testBrokerCloneWithoutAudience_new() {
		OAuth2TokenValidatorResult result = new XsuaaCloneTokenValidator(serviceConfigurationBrokerPlan.getClientId(), serviceConfigurationBrokerPlan.getAppId())
				.validate(cloneTokenWithAudience);
		Assert.assertFalse(result.hasErrors());
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
