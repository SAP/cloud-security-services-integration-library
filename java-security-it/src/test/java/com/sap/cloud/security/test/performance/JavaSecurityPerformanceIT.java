/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.performance;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.test.SecurityTest;
import com.sap.cloud.security.test.performance.util.BenchmarkUtil;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.ServiceConstants.XSUAA.VERIFICATION_KEY;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Performance test for java-security jwt token validation.
 */
class JavaSecurityPerformanceIT {

	private static final Logger LOGGER = LoggerFactory.getLogger(JavaSecurityPerformanceIT.class);
	private static SecurityTest securityTest;

	@BeforeAll
	static void setUp() throws Exception {
		securityTest = new SecurityTest(XSUAA).setKeys("/publicKey.txt", "/privateKey.txt");
		securityTest.setup();
		LOGGER.debug(BenchmarkUtil.getSystemInfo());
	}

	@AfterAll
	static void tearDown() {
		securityTest.tearDown();
	}

	@Test
	void onlineValidation() {
		Token token = securityTest.createToken();
		CombiningValidator<Token> tokenValidator = createOnlineTokenValidator();
		ValidationResult validationResult = tokenValidator.validate(token);
		assertThat(validationResult.isValid()).isTrue();
		String tokenValue = token.getTokenValue();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> tokenValidator.validate(new XsuaaToken(tokenValue)));
		LOGGER.info("Online validation result: {}", result);
	}

	@Test
	void offlineValidation() throws Exception {
		Token token = securityTest.createToken();
		CombiningValidator<Token> tokenValidator = createOfflineTokenValidator();
		ValidationResult validationResult = tokenValidator.validate(token);
		assertThat(validationResult.isValid()).isTrue();
		String tokenValue = token.getTokenValue();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> tokenValidator.validate(new XsuaaToken(tokenValue)));
		LOGGER.info("Offline validation result: {}", result);
	}

	private CombiningValidator<Token> createOfflineTokenValidator() throws IOException {
		String publicKey = IOUtils.resourceToString("/publicKey.txt", StandardCharsets.UTF_8);
		OAuth2ServiceConfiguration configuration = createConfigurationBuilder()
				.withProperty(VERIFICATION_KEY, publicKey)
				.build();
		return JwtValidatorBuilder.getInstance(configuration)
				// oAuth2TokenKeyService mocked because verificationkey property is used for offline token validation
				.withOAuth2TokenKeyService((uri, zoneId) -> "{\"keys\": []}")
				.build();
	}

	private CombiningValidator<Token> createOnlineTokenValidator() {
		return JwtValidatorBuilder.getInstance(createConfigurationBuilder().build()).build();
	}

	private OAuth2ServiceConfigurationBuilder createConfigurationBuilder() {
		return OAuth2ServiceConfigurationBuilder.forService(XSUAA)
				.withProperty(ServiceConstants.XSUAA.UAA_DOMAIN, SecurityTest.DEFAULT_DOMAIN)
				.withProperty(ServiceConstants.XSUAA.APP_ID, SecurityTest.DEFAULT_APP_ID)
				.withClientId(SecurityTest.DEFAULT_CLIENT_ID);
	}

}

