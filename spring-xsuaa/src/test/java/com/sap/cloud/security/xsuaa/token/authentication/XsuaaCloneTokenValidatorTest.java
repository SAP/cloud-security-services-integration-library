package com.sap.cloud.security.xsuaa.token.authentication;

import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.Token;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

public class XsuaaCloneTokenValidatorTest {

	private JWTClaimsSet.Builder claimsBuilder;
	private String XSUAA_BROKER_XSAPPNAME = "brokerplanmasterapp!b123";
	private String XSUAA_BROKER_CLIENT_ID = "sb-" + XSUAA_BROKER_XSAPPNAME;
	private XsuaaCloneTokenValidator cut;

	@Before
	public void setup() {
		cut = new XsuaaCloneTokenValidator(XSUAA_BROKER_CLIENT_ID, XSUAA_BROKER_XSAPPNAME);

		claimsBuilder = new JWTClaimsSet.Builder().issueTime(new Date()).expirationTime(JwtGenerator.NO_EXPIRE_DATE);
		claimsBuilder.claim(Token.CLIENT_ID, "sb-clone1!b22|" + XSUAA_BROKER_XSAPPNAME);
	}

	@Test
	public void tokenWithClientId_like_brokerClientId_shouldBeIgnored() {
		claimsBuilder.claim(Token.CLIENT_ID, XSUAA_BROKER_CLIENT_ID);

		OAuth2TokenValidatorResult result = cut.validate(JwtGenerator.createFromClaims(claimsBuilder.build()));
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void cloneTokenClientId_like_brokerClientId_shouldBeAccepted() {
		claimsBuilder.claim(Token.CLIENT_ID, "sb-clone1!b22|" + XSUAA_BROKER_XSAPPNAME);

		OAuth2TokenValidatorResult result = cut.validate(JwtGenerator.createFromClaims(claimsBuilder.build()));
		Assert.assertFalse(result.hasErrors());
	}

	@Test
	public void cloneTokenClientId_unlike_brokerClientId_raisesError() {
		claimsBuilder.claim(Token.CLIENT_ID, "sb-clone1!b22|ANOTHERAPP!b12");

		OAuth2TokenValidatorResult result = cut.validate(JwtGenerator.createFromClaims(claimsBuilder.build()));
		Assert.assertTrue(result.hasErrors());
	}

	@Test
	public void applicationTokenClientId_shouldBeIgnored() {
		claimsBuilder.claim(Token.CLIENT_ID, "sb-anyapp!t22");

		OAuth2TokenValidatorResult result = cut.validate(JwtGenerator.createFromClaims(claimsBuilder.build()));
		Assert.assertFalse(result.hasErrors());
	}
}
