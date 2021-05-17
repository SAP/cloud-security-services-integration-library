/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.*;

class XsuaaServiceConfigurationTest {

	private final ApplicationContextRunner runner = new ApplicationContextRunner();

	@EnableConfigurationProperties(XsuaaServiceConfiguration.class)
	static class EnablePropertiesConfiguration {
	}

	@Test
	void configuresXsuaaServiceConfiguration() {
		runner.withUserConfiguration(EnablePropertiesConfiguration.class)
				.withPropertyValues("sap.security.services.xsuaa.url:http://localhost",
						"sap.security.services.xsuaa.uaadomain:localhost", "sap.security.services.xsuaa.clientid:cid")
				.run(context -> {
					assertEquals("http://localhost",
							context.getBean(XsuaaServiceConfiguration.class).getUrl().toString());
				});
	}
}
