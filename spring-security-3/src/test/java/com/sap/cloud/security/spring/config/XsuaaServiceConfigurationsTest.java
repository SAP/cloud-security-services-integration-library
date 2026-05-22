/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XsuaaServiceConfigurationsTest {

	private final ApplicationContextRunner runner = new ApplicationContextRunner();

	@EnableConfigurationProperties({ XsuaaServiceConfigurations.class, XsuaaServiceConfiguration.class })
	static class EnablePropertiesConfiguration {
	}

	@Test
	void configuresXsuaaServiceConfigurations() {
		runner.withUserConfiguration(EnablePropertiesConfiguration.class)
				.withPropertyValues(
						"sap.security.services.xsuaa[0].clientid:cid0",
						"sap.security.services.xsuaa[0].name:xsuaaInstance0",
						"sap.security.services.xsuaa[0].plan:broker")
				.withPropertyValues(
						"sap.security.services.xsuaa[1].clientid:cid1",
						"sap.security.services.xsuaa[1].name:xsuaaInstance1",
						"sap.security.services.xsuaa[1].plan:broker")
				.run(context -> {
					XsuaaServiceConfiguration config0 = context.getBean(XsuaaServiceConfigurations.class)
							.getConfigurations().get(0);
					assertEquals("cid0", config0.getClientId());
					assertEquals("xsuaaInstance0", config0.getName());
					assertEquals("broker", config0.getPlan());

					XsuaaServiceConfiguration config1 = context.getBean(XsuaaServiceConfigurations.class)
							.getConfigurations().get(1);
					assertEquals("cid1", config1.getClientId());
					assertEquals("xsuaaInstance1", config1.getName());
					assertEquals("broker", config1.getPlan());
				});
	}
}
