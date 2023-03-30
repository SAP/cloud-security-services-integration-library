/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.integration;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.junit.ClassRule;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IAS integration test with single binding scenario.
 */
public class IasIntegrationTest {

	@ClassRule
	public static SecurityTestRule rule = SecurityTestRule.getInstance(Service.IAS)
			.setKeys("/publicKey.txt", "/privateKey.txt");

	@Test
	public void iasTokenValidationSucceeds_withIasCombiningValidator() throws IOException {
		OAuth2ServiceConfiguration configuration = rule
				.getOAuth2ServiceConfigurationBuilderFromFile("/ias-simple/vcap_services-single.json")
				.build();

		Token iasToken = rule.getJwtGeneratorFromFile("/ias-simple/token.json")
				//.withClaimValue("iss", "https://application.myauth.com") // required for java-security/src/test/resources/iasOidcTokenRSA256.txt
				.createToken();
		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();

		ValidationResult result = tokenValidator.validate(iasToken);
		assertThat(result.isValid()).isTrue();
	}

}
