/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.integration;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.junit.ClassRule;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests multiple bindings which is not supported by {@link com.sap.cloud.security.config.cf.VcapServicesParser}
 * and {@link com.sap.cloud.security.test.SecurityTest}.
 */
public class XsuaaMultipleBindingsIntegrationTest {

	@ClassRule
	public static SecurityTestRule rule = SecurityTestRule.getInstance(Service.XSUAA)
			.setKeys("/publicKey.txt", "/privateKey.txt");

	@Test
	public void createToken_integrationTest_tokenValidation() {
		Token token = rule.getPreconfiguredJwtGenerator().createToken();
		OAuth2ServiceConfiguration configuration = Environments.readFromInput(XsuaaMultipleBindingsIntegrationTest.class.getResourceAsStream("/vcap_services-multiple.json")).getXsuaaConfiguration();
		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

}
