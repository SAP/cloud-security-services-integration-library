/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.performance;

import com.sap.cloud.security.test.SecurityTest;
import com.sap.cloud.security.test.performance.util.BenchmarkUtil;
import com.sap.cloud.security.xsuaa.XsuaaCredentials;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationCustom;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Performance test for spring-xsuaa jwt token validation.
 */
class SpringXsuaaPerformanceIT {

	private static final Logger LOGGER = LoggerFactory.getLogger(SpringXsuaaPerformanceIT.class);
	private static SecurityTest securityTest;
	private static JwtDecoder jwtDecoder;
	private static String token;

	@BeforeAll
	static void setUp() throws Exception {
		LOGGER.debug(BenchmarkUtil.getSystemInfo());
		securityTest = new SecurityTest(XSUAA).setKeys("/publicKey.txt", "/privateKey.txt");
		jwtDecoder = createJwtDecoder();
		securityTest.setup();
		token = securityTest.createToken().getTokenValue();
	}

	@AfterAll
	static void tearDown() {
		securityTest.tearDown();
	}

	@Test
	void onlineValidation() {
		assertThat(securityTest.getWireMockServer().isRunning()).isTrue();
		assertThat(jwtDecoder.decode(token)).isNotNull();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> jwtDecoder.decode(token));
		LOGGER.info("Online validation result: {}", result);
	}

	@Test
	void offlineValidation() {
		securityTest.tearDown(); // to test offline validation oauth2 server needs to be shut down

		assertThat(securityTest.getWireMockServer().isRunning()).isFalse();
		assertThat(jwtDecoder.decode(token)).isNotNull();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> jwtDecoder.decode(token));
		LOGGER.info("Offline validation result: {}", result);
	}

	private static JwtDecoder createJwtDecoder() throws IOException {
		XsuaaServiceConfigurationCustom configuration = new XsuaaServiceConfigurationCustom(createXsuaaCredentials());
		return new XsuaaJwtDecoderBuilder(configuration).build();
	}

	private static XsuaaCredentials createXsuaaCredentials() throws IOException {
		final String publicKey = IOUtils.resourceToString("/publicKey.txt", StandardCharsets.UTF_8);

		XsuaaCredentials xsuaaCredentials = new XsuaaCredentials();
		xsuaaCredentials.setUaaDomain(SecurityTest.DEFAULT_DOMAIN);
		xsuaaCredentials.setClientId(SecurityTest.DEFAULT_CLIENT_ID);
		xsuaaCredentials.setXsAppName(SecurityTest.DEFAULT_APP_ID);
		xsuaaCredentials.setVerificationKey(publicKey.replace("\n", ""));
		return xsuaaCredentials;
	}

}

