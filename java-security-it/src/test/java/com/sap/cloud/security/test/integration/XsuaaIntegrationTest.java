/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.integration;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import org.apache.commons.io.IOUtils;
import org.junit.ClassRule;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.VERIFICATION_KEY;
import static com.sap.cloud.security.test.SecurityTestRule.DEFAULT_CLIENT_ID;
import static com.sap.cloud.security.test.SecurityTestRule.DEFAULT_DOMAIN;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Xsuaa integration test with single binding scenario.
 */
public class XsuaaIntegrationTest {

	@ClassRule
	public static SecurityTestRule rule = SecurityTestRule.getInstance(Service.XSUAA)
			.setKeys("/publicKey.txt", "/privateKey.txt");

	@Test
	public void xsuaaTokenValidationSucceeds_withXsuaaCombiningValidator() {
		OAuth2ServiceConfigurationBuilder configuration = rule.getOAuth2ServiceConfigurationBuilderFromFile(
				"/xsuaa/vcap_services-single.json");
		Token token = rule.getJwtGeneratorFromFile("/xsuaa/token.json").createToken();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration.build()).build();
		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void xsaTokenValidationSucceeds_withXsuaaCombiningValidator() throws IOException {
		OAuth2ServiceConfiguration configuration = rule.getOAuth2ServiceConfigurationBuilderFromFile(
				"/xsa-simple/vcap_services-single.json")
				.runInLegacyMode(true)
				.build();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();

		Token token = rule.getJwtGeneratorFromFile("/xsa-simple/token.json").createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void xsuaaTokenValidationFails_withIasCombiningValidator() {
		OAuth2ServiceConfiguration configuration = rule.getOAuth2ServiceConfigurationBuilderFromFile(
				"/ias-simple/vcap_services-single.json")
				.withDomains("myauth.com")
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
				"Issuer http://auth.com was not a trusted domain or a subdomain of the trusted domains [myauth.com].");
	}

	@Test
	public void uaaTokenValidationSucceeds_withXsuaaCombiningValidator() {
		OAuth2ServiceConfigurationBuilder configuration = rule.getOAuth2ServiceConfigurationBuilderFromFile(
				"/uaa/vcap_services.json");
		Token token = rule.getJwtGeneratorFromFile("/uaa/token.json")
				//.withHeaderParameter("jku", "http://auth.com/token_keys")  // required to create uaaAccessTokenRSA.txt
				//.withHeaderParameter("kid", "key-id-0")
				.createToken();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration.build()).build();
		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void createToken_withCorrectVerificationKey_tokenIsValid() throws IOException {
		String publicKey = IOUtils.resourceToString("/publicKey.txt", StandardCharsets.UTF_8);
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(XSUAA)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, DEFAULT_DOMAIN)
				.withClientId(DEFAULT_CLIENT_ID)
				.withProperty(VERIFICATION_KEY, publicKey)
				.build();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				// mocked because we use the key from the verificationkey property here
				.withOAuth2TokenKeyService(Mockito.mock(OAuth2TokenKeyService.class))
				.build();

		Token token = rule.getPreconfiguredJwtGenerator().createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}
}
