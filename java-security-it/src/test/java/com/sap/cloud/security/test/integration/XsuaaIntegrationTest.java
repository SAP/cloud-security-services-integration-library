package com.sap.cloud.security.test.integration;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.junit.ClassRule;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class XsuaaIntegrationTest {

	@ClassRule
	public static SecurityTestRule rule = SecurityTestRule.getInstance(Service.XSUAA)
			.setKeys("/publicKey.txt", "/privateKey.txt");

	@Test
	public void xsuaaTokenValidationSucceeds_withXsuaaCombiningValidator() throws IOException {
		OAuth2ServiceConfigurationBuilder configuration = rule.getConfigurationBuilderFromFile(
				"/xsuaa/vcap_services-single.json");
		Token token = rule.getJwtGeneratorFromFile("/xsuaa/token.json").createToken();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration.build()).build();
		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void xsaTokenValidationSucceeds_withXsuaaCombiningValidator() throws IOException {
		OAuth2ServiceConfiguration configuration = rule.getConfigurationBuilderFromFile(
				"/xsa-simple/vcap_services-single.json")
				.runInLegacyMode(true)
				.build();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();

		Token token = rule.getJwtGeneratorFromFile("/xsa-simple/token.json").createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void xsuaaTokenValidationFails_withIasCombiningValidator() throws IOException {
		OAuth2ServiceConfiguration configuration = rule.getConfigurationBuilderFromFile(
				"/ias-simple/vcap_services-single.json")
				.withUrl("https://myauth.com")
				.build();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				.build();

		Token token = rule.getJwtGeneratorFromFile("/xsuaa/token.json")
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, "T000310")
				.withClaimValue(TokenClaims.ISSUER, "http://auth.com")
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrorDescription()).startsWith(
				"Issuer is not trusted because 'iss' 'http://auth.com' does not match host 'myauth.com' of the identity provider");
	}

}
