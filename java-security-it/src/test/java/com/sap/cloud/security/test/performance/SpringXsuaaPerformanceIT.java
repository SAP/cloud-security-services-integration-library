/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.performance;

import com.sap.cloud.security.test.SecurityTest;
import com.sap.cloud.security.test.performance.util.BenchmarkUtil;
import com.sap.cloud.security.xsuaa.XsuaaCredentials;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
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

	@BeforeAll
	static void setUp() throws Exception {
		LOGGER.debug(BenchmarkUtil.getSystemInfo());
		securityTest = new SecurityTest(XSUAA).setKeys("/publicKey.txt", "/privateKey.txt");
		securityTest.setup();
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
		LOGGER.info("Online validation result: {}", result.toString());
	}

	@Test
	void offlineValidation() throws Exception {
		String token = securityTest.createToken().getTokenValue();
		JwtDecoder jwtDecoder = createOfflineJwtDecoder();
		assertThat(jwtDecoder.decode(token)).isNotNull();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> jwtDecoder.decode(token));
		LOGGER.info("Offline validation result: {}", result.toString());
	}

	private JwtDecoder createOnlineJwtDecoder() {
		XsuaaServiceConfigurationCustom configuration = new XsuaaServiceConfigurationCustom(createXsuaaCredentials());
		return new XsuaaJwtDecoderBuilder(configuration).build();
	}

	private JwtDecoder createOfflineJwtDecoder() throws IOException {
		final XsuaaCredentials xsuaaCredentials = createXsuaaCredentials();
		// Workaround because RestOperations cannot easily be switched off
		xsuaaCredentials.setUaaDomain("__nonExistingUaaDomainForOfflineTesting__");
		final String publicKey = IOUtils.resourceToString("/publicKey.txt", StandardCharsets.UTF_8);
		final XsuaaServiceConfiguration xsuaaConfig = new XsuaaServiceConfigurationCustom(xsuaaCredentials) {
			@Override
			public String getVerificationKey() {
				return publicKey.replace("\n", "");
			}
		};
		return new XsuaaJwtDecoderBuilder(xsuaaConfig).build();
	}

	private XsuaaCredentials createXsuaaCredentials() {
		XsuaaCredentials xsuaaCredentials = new XsuaaCredentials();
		xsuaaCredentials.setUaaDomain(SecurityTest.DEFAULT_DOMAIN);
		xsuaaCredentials.setClientId(SecurityTest.DEFAULT_CLIENT_ID);
		xsuaaCredentials.setXsAppName(SecurityTest.DEFAULT_APP_ID);
		return xsuaaCredentials;
	}

}

