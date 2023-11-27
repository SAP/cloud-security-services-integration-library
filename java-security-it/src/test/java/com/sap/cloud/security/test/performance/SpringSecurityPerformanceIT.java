/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.performance;

import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.test.SecurityTest;
import com.sap.cloud.security.test.performance.util.BenchmarkUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.JwtDecoder;

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
		LOGGER.info("Online validation result (xsuaa): {}", result);
	}

	@Test
	void onlineIasValidation() {
		String token = securityIasTest.createToken().getTokenValue();
		JwtDecoder jwtDecoder = createOnlineJwtDecoder();
		assertThat(jwtDecoder.decode(token)).isNotNull();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> jwtDecoder.decode(token));
		LOGGER.info("Online validation result (identity): {}", result);
	}

	private JwtDecoder createOnlineJwtDecoder() {
		return new JwtDecoderBuilder()
				.withIasServiceConfiguration(createIasConfigurationBuilder().build())
				.withXsuaaServiceConfiguration(createXsuaaConfigurationBuilder().build()).build();
	}

	private OAuth2ServiceConfigurationBuilder createXsuaaConfigurationBuilder() {
		return OAuth2ServiceConfigurationBuilder.forService(XSUAA)
				.withProperty(ServiceConstants.XSUAA.UAA_DOMAIN, securityTest.getWireMockServer().baseUrl())
				.withProperty(ServiceConstants.XSUAA.APP_ID, SecurityTest.DEFAULT_APP_ID)
				.withClientId(SecurityTest.DEFAULT_CLIENT_ID);
	}

	private OAuth2ServiceConfigurationBuilder createIasConfigurationBuilder() {
		return OAuth2ServiceConfigurationBuilder.forService(IAS)
				.withDomains(securityIasTest.getWireMockServer().baseUrl())
				.withClientId(SecurityTest.DEFAULT_CLIENT_ID);
	}
}

