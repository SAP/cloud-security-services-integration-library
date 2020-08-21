package com.sap.cloud.security.test.integration;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.VcapServicesParser;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.Token;
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
		OAuth2ServiceConfiguration configuration = VcapServicesParser.fromFile("/xsuaa/vcapServices/singleBinding.json")
				.createConfiguration();
		Token token = rule.getPreconfiguredJwtGenerator()
				.fromFile("/xsuaa/tokens/userAccessTokenRSA256.json")
				.createToken();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();
		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void xsaTokenValidationSucceeds_withXsuaaCombiningValidator() throws IOException {
		OAuth2ServiceConfiguration configuration = VcapServicesParser.fromFile(
				"/xsuaa/vcapServices/xsaSingleBinding.json")
				.runInLegacyMode(true)
				.withUrl(rule.getWireMockServer().baseUrl()) // overridden because of legacy mode
				.createConfiguration();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();

		Token token = rule.getPreconfiguredJwtGenerator()
				.fromFile("/xsuaa/tokens/xsaAccessToken.json")
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

}
