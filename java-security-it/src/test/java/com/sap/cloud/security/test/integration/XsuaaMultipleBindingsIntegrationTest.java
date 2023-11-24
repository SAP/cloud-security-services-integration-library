/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.integration;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.junit.ClassRule;
import org.junit.Test;
import org.mockito.Mockito;

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
		OAuth2ServiceConfiguration mockConfig = Mockito.mock(OAuth2ServiceConfiguration.class);
		Mockito.when(mockConfig.getClientId()).thenReturn(configuration.getClientId());
		Mockito.when(mockConfig.getDomains()).thenReturn(configuration.getDomains());
		Mockito.when(mockConfig.getUrl()).thenReturn(configuration.getUrl());
		Mockito.when(mockConfig.hasProperty(CFConstants.XSUAA.APP_ID)).thenReturn(configuration.hasProperty(CFConstants.XSUAA.APP_ID));
		Mockito.when(mockConfig.getProperty(CFConstants.XSUAA.APP_ID)).thenReturn(configuration.getProperty(CFConstants.XSUAA.APP_ID));
		Mockito.when(mockConfig.getProperty(CFConstants.XSUAA.UAA_DOMAIN)).thenReturn(rule.getWireMockServer().baseUrl());
		Mockito.when(mockConfig.getService()).thenReturn(configuration.getService());

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(mockConfig).build();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

}
