package com.sap.cloud.security.xsuaa.token.authentication;

import com.sap.cloud.security.xsuaa.token.JwtGenerator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;


public class XsuaaAudienceValidatorTest {

	private Jwt tokenWithAudience = null;
	private Jwt tokenWithoutAudience = null;

	@Before
	public void setup() throws Exception {
		tokenWithAudience = JwtGenerator.createFromTemplate("/audience_1.txt");
		tokenWithoutAudience= JwtGenerator.createFromTemplate("/audience_2.txt");
	}
	@Test
	public void testSameClientId()
	{
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(new DummyXsuaaServiceConfiguration("sb-test1!t1","test1!t1")).validate(tokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testSameClientIdWithoutAudience()
	{
		OAuth2TokenValidatorResult result2 = new XsuaaAudienceValidator(new DummyXsuaaServiceConfiguration("sb-test1!t1","test1!t1")).validate(tokenWithoutAudience);
		Assert.assertFalse(result2.hasErrors());
	}

	@Test
	public void testOtherGrantedClientId()
	{
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(new DummyXsuaaServiceConfiguration("sb-test2!t1","test2!t1")).validate(tokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}
	@Test
	public void testOtherGrantedClientIdWithoutAudience()
	{
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(new DummyXsuaaServiceConfiguration("sb-test2!t1","test2!t1")).validate(tokenWithoutAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndDot()
	{
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(new DummyXsuaaServiceConfiguration("sb-test4!t1","test4!t1")).validate(tokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void testUnGrantedClientId()
	{
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(new DummyXsuaaServiceConfiguration("sb-test3!t1","test3!t1")).validate(tokenWithAudience);
		Assert.assertTrue(result.hasErrors());
	}


	class DummyXsuaaServiceConfiguration implements XsuaaServiceConfiguration
	{

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
