/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.performance;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.cf.ServiceConstants;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.test.SecurityTest;
import com.sap.cloud.security.test.performance.util.BenchmarkUtil;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Performance test for spring-xsuaa jwt token validation.
 */
class SpringSecurityPerformanceIT {

	private static final Logger LOGGER = LoggerFactory.getLogger(SpringSecurityPerformanceIT.class);
	private static SecurityTest securityTest;
	private static SecurityTest securityIasTest;

	@BeforeAll
	static void setUp() throws Exception {
		LOGGER.debug(BenchmarkUtil.getSystemInfo());
		securityTest = new SecurityTest(XSUAA).setKeys("/publicKey.txt", "/privateKey.txt");
		securityTest.setup();
		securityIasTest = new SecurityTest(IAS).setKeys("/publicKey.txt", "/privateKey.txt");
		securityIasTest.setup();
		LOGGER.debug(BenchmarkUtil.getSystemInfo());
	}

	@AfterAll
	static void tearDown() {
		securityTest.tearDown();
	}

	@Test
	void onlineValidation() {
		String token = securityTest.createToken().getTokenValue();
		JwtDecoder jwtDecoder = createOnlineJwtDecoder();
		assertThat(jwtDecoder.decode(token)).isNotNull();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> jwtDecoder.decode(token));
		LOGGER.info("Online validation result (xsuaa): {}", result.toString());
	}

	@Test
	void onlineIasValidation() {
		String token = securityIasTest.createToken().getTokenValue();
		JwtDecoder jwtDecoder = createOnlineJwtDecoder();
		assertThat(jwtDecoder.decode(token)).isNotNull();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> jwtDecoder.decode(token));
		LOGGER.info("Online validation result (identity): {}", result.toString());
	}

	// @Test
	void offlineValidation() throws Exception {
		String token = securityTest.createToken().getTokenValue();
		JwtDecoder jwtDecoder = createOfflineJwtDecoder();
		assertThat(jwtDecoder.decode(token)).isNotNull();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> jwtDecoder.decode(token));
		LOGGER.info("Offline validation result: {}", result.toString());
	}

	private JwtDecoder createOnlineJwtDecoder() {
		return new JwtDecoderBuilder()
				.withIasServiceConfiguration(createIasConfigurationBuilder().build())
				.withXsuaaServiceConfiguration(createXsuaaConfigurationBuilder().build()).build();
	}

	private JwtDecoder createOfflineJwtDecoder() throws IOException {
		final String publicKey = IOUtils.resourceToString("/publicKey.txt", StandardCharsets.UTF_8)
				.replace("\n", "");
		OAuth2ServiceConfiguration configuration = createXsuaaConfigurationBuilder()
				.withProperty("verificationkey", publicKey)
				.build();
		return new JwtDecoderBuilder()
				.withIasServiceConfiguration(createIasConfigurationBuilder().build())
				.withXsuaaServiceConfiguration(configuration).build();
	}

	private OAuth2ServiceConfigurationBuilder createXsuaaConfigurationBuilder() {
		return OAuth2ServiceConfigurationBuilder.forService(XSUAA)
				.withProperty(ServiceConstants.XSUAA.UAA_DOMAIN, SecurityTest.DEFAULT_DOMAIN)
				.withProperty(ServiceConstants.XSUAA.APP_ID, SecurityTest.DEFAULT_APP_ID)
				.withClientId(SecurityTest.DEFAULT_CLIENT_ID);
	}

	private OAuth2ServiceConfigurationBuilder createIasConfigurationBuilder() {
		return OAuth2ServiceConfigurationBuilder.forService(IAS)
				.withDomains(SecurityTest.DEFAULT_DOMAIN)
				.withClientId(SecurityTest.DEFAULT_CLIENT_ID);
	}
}

