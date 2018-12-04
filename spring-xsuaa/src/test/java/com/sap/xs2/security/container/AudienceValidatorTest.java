package com.sap.xs2.security.container;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.authentication.AudienceValidator;




public class AudienceValidatorTest {

	private Jwt tokenWithAudience = null;
	private Jwt tokenWithoutAudience = null;

	@Before
	public void setup() throws Exception {
		tokenWithAudience = UserInfoTestUtil.parseJwt(UserInfoTestUtil.createJWT("/audience_1.txt"));	
		tokenWithoutAudience= UserInfoTestUtil.parseJwt(UserInfoTestUtil.createJWT("/audience_2.txt"));
	}
	@Test
	public void testSameClientId()
	{
		OAuth2TokenValidatorResult result = new AudienceValidator(new DummyXsuaaServiceConfiguration("sb-test1!t1","test1!t1")).validate(tokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}
	
	@Test
	public void testSameClientIdWithoutAudience()
	{
		OAuth2TokenValidatorResult result2 = new AudienceValidator(new DummyXsuaaServiceConfiguration("sb-test1!t1","test1!t1")).validate(tokenWithoutAudience);
		Assert.assertFalse(result2.hasErrors());
	}

	@Test
	public void testOtherGrantedClientId()
	{
		OAuth2TokenValidatorResult result = new AudienceValidator(new DummyXsuaaServiceConfiguration("sb-test2!t1","test2!t1")).validate(tokenWithAudience);
		Assert.assertFalse(result.hasErrors());
	}
	@Test
	public void testOtherGrantedClientIdWithoutAudience()
	{
		OAuth2TokenValidatorResult result = new AudienceValidator(new DummyXsuaaServiceConfiguration("sb-test2!t1","test2!t1")).validate(tokenWithoutAudience);
		Assert.assertFalse(result.hasErrors());
	}
	

	@Test
	public void testUnGrantedClientId()
	{
		OAuth2TokenValidatorResult result = new AudienceValidator(new DummyXsuaaServiceConfiguration("sb-test3!t1","test3!t1")).validate(tokenWithAudience);
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
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public String getUaaUrl() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public String getTokenKeyUrl(String zid, String subdomain) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public String getAppId() {
			return xsAppId;
		}
		
	}
}
