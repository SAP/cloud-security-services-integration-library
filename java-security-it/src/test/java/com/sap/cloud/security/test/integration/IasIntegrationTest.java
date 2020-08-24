package com.sap.cloud.security.test.integration;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.VcapServicesParser;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.junit.ClassRule;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class IasIntegrationTest {

	@ClassRule
	public static SecurityTestRule rule = SecurityTestRule.getInstance(Service.IAS)
			.setKeys("/publicKey.txt", "/privateKey.txt");


	@Test
	public void iasTokenValidationSucceeds_withIasCombiningValidator() throws IOException {
		OAuth2ServiceConfiguration configuration = VcapServicesParser
				.fromFile("/ias/vcapServices/serviceSingleBinding.json")
				.createConfiguration();

		Token iasToken = rule.getPreconfiguredJwtGenerator()
				.fromFile("/ias/tokens/oidcTokenRSA256.json")
				.createToken();
		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();

		ValidationResult result = tokenValidator.validate(iasToken);
		assertThat(result.isValid()).isTrue();
	}


	@Test
	public void xsuaaTokenValidationFails_withIasCombiningValidator() throws IOException {
		OAuth2ServiceConfiguration configuration = VcapServicesParser
				.fromFile("/ias/vcapServices/serviceSingleBinding.json")
				.withUrl("https://myauth.com")
				.createConfiguration();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				.build();

		Token token = SecurityTestRule.getInstance(Service.XSUAA).getPreconfiguredJwtGenerator()
				.fromFile("/xsuaa/tokens/userAccessTokenRSA256.json")
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, "T000310")
				.withClaimValue(TokenClaims.ISSUER, "http://auth.com")
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrorDescription()).startsWith(
				"Issuer is not trusted because 'iss' 'http://auth.com' does not match host 'myauth.com' of the identity provider");
	}
}
