/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class XsuaaTokenFlowAutoConfigurationTest {

	private final List<String> properties = new ArrayList<>();
	private ApplicationContextRunner runner;
	private static String cert;
	private static String key;

	@BeforeAll
	static void init() throws IOException {
		cert = IOUtils.resourceToString("/certificate.txt", StandardCharsets.UTF_8);
		key = IOUtils.resourceToString("/key.txt", StandardCharsets.UTF_8);
	}

	@BeforeEach
	void setup() {
		properties.add("sap.security.services.xsuaa.url:http://localhost");
		properties.add("sap.security.services.xsuaa.clientid:cid");
		properties.add("sap.security.services.xsuaa.clientsecret:pwd");

		runner = new ApplicationContextRunner()
				.withPropertyValues(properties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class,
						XsuaaTokenFlowAutoConfiguration.class));
	}

	@Test
	void autoConfigurationActive() {
		runner.run(context -> assertNotNull(context.getBean("xsuaaTokenFlows", XsuaaTokenFlows.class)));
	}

	@Test
	void autoConfigurationActiveInclProperties() {
		runner.withPropertyValues("sap.spring.security.xsuaa.flows.auto:true").run((context) -> assertNotNull(context.getBean("xsuaaTokenFlows", XsuaaTokenFlows.class)));
	}

	@Test
	void configures_xsuaaMtlsTokenFlows_withProperties() {
		runner
				.withPropertyValues("sap.spring.security.xsuaa.flows.auto:true")
				.withPropertyValues("sap.security.services.xsuaa.credential-type:x509")
				.withPropertyValues("sap.security.services.xsuaa.certificate:" + cert)
				.withPropertyValues("sap.security.services.xsuaa.key:" + key)
				.run((context) -> {
					assertThat(context).hasSingleBean(XsuaaTokenFlows.class);
					assertThat(context).hasBean("xsuaaMtlsTokenFlows");
				});
	}

	@Test
	void autoConfigurationDisabledByProperty() {
		runner.withPropertyValues("sap.spring.security.xsuaa.flows.auto:false").run((context) -> assertFalse(context.containsBean("xsuaaTokenFlows")));
	}

	@Test
	void autoConfigurationDisabledWhenNoClientSecretIsGiven() {
		WebApplicationContextRunner mt_runner;

		mt_runner = new WebApplicationContextRunner()
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class,
						XsuaaTokenFlowAutoConfiguration.class));

		mt_runner.run(context -> assertFalse(context.containsBean("xsuaaTokenFlows")));
	}

	@Test
	void autoConfigurationUsesTokenFlowsForMultipleXsuaaServicesAsPrimary() {
		WebApplicationContextRunner mt_runner;

		List<String> mt_properties = new ArrayList<>(properties);
		mt_properties.add("sap.security.services.xsuaa[0].url:http://localhost");
		mt_properties.add("sap.security.services.xsuaa[0].clientid:cid");
		mt_properties.add("sap.security.services.xsuaa[0].clientsecret:pwd");
		mt_properties.add("sap.security.services.xsuaa[1].clientid:cid");

		mt_runner = new WebApplicationContextRunner()
				.withPropertyValues(mt_properties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class,
						XsuaaTokenFlowAutoConfiguration.class));

		mt_runner.run(context -> assertTrue(context.containsBean("xsuaaTokenFlows")));
	}

	@Test
	void userConfigurationCanOverrideDefaultBeans() {
		runner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertFalse(context.containsBean("xsuaaTokenFlows"));
					assertNotNull(context.getBean("customTokenFlows", XsuaaTokenFlows.class));
				});
	}

	@Configuration
	static class UserConfiguration {

		@Bean
		public XsuaaTokenFlows customTokenFlows() {
			return Mockito.mock(XsuaaTokenFlows.class);
		}
	}
}
