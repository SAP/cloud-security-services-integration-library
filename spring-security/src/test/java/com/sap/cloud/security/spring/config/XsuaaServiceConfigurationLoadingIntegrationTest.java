/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceBindingEnvironment;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.io.IOException;
import java.util.List;

import static com.sap.cloud.security.spring.config.ConfigurationUtil.assertConfigsAreEqual;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(classes = { MultipleXsuaaConfigurationsFromFile.class })
class XsuaaServiceConfigurationsLoadingIntegrationTest {

	static ServiceBindingEnvironment env;

	@Autowired
	XsuaaServiceConfigurations configs;

	@BeforeAll
	static void setup() throws IOException {
		String serviceBindingJson = IOUtils.resourceToString("/fourXsuaaBindingsAndOneIasBinding.json", UTF_8);
		env = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> serviceBindingJson));
	}

	@Test
	void configuresXsuaaServiceConfigurations() {
		List<XsuaaServiceConfiguration> configList = configs.getConfigurations();

		/* Index 0 backward-compatible behaviour */
		assertConfigsAreEqual(configList.get(0), env.getXsuaaConfiguration());

		/* Index 1 backward-compatible behaviour */
		assertConfigsAreEqual(configList.get(1), env.getXsuaaConfigurationForTokenExchange());

		/* Index 2+ */
		assertEquals(env.getServiceConfigurationsAsList().get(Service.XSUAA).size(), configList.size());
	}
}

@Configuration
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, value = { "classpath:fourXsuaaBindingsAndOneIasBinding.json" })
@EnableConfigurationProperties(XsuaaServiceConfigurations.class)
class MultipleXsuaaConfigurationsFromFile {}