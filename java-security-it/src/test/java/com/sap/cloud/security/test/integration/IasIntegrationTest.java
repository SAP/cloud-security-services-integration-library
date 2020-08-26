package com.sap.cloud.security.test.integration;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
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
		OAuth2ServiceConfiguration configuration = rule
				.getConfigurationBuilderFromFile("/ias/vcapServices/serviceSingleBinding.json")
				.build();

		Token iasToken = rule.getJwtGeneratorFromFile("/ias/tokens/oidcTokenRSA256.json")
				.createToken();
		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();

		ValidationResult result = tokenValidator.validate(iasToken);
		assertThat(result.isValid()).isTrue();
	}

}
