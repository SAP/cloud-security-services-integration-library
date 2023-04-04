/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.apache.commons.io.IOUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
		runner.withClassLoader(new FilteredClassLoader(CloseableHttpClient.class)).run(context -> {
			assertThat(context).hasSingleBean(CloseableHttpClient.class);
			assertThat(context).hasBean("httpClient");
			assertNotNull(context.getBean("xsuaaTokenFlows", XsuaaTokenFlows.class));
		});
	}

	@Test
	void autoConfigurationActiveInclProperties() {
		runner.withPropertyValues("sap.spring.security.xsuaa.flows.auto:true")
				.run((context) -> assertNotNull(context.getBean("xsuaaTokenFlows", XsuaaTokenFlows.class)));
	}

	@Test
	void configures_singleXsuaa_httpClient() {
		runner = new ApplicationContextRunner()
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class,
						XsuaaTokenFlowAutoConfiguration.class))
				.withPropertyValues("sap.security.services.xsuaa.certurl:https://domain.cert.auth.com")
				.withPropertyValues("sap.security.services.xsuaa.clientid:cid")
				.withPropertyValues("sap.security.services.xsuaa.certificate:" + cert)
				.withPropertyValues("sap.security.services.xsuaa.key:" + key)
				.run((context) -> {
					assertThat(context).hasSingleBean(CloseableHttpClient.class);
					assertThat(context).hasBean("httpClient");
				});
	}

	@Test
	void autoConfigurationDisabledByProperty() {
		runner.withPropertyValues("sap.spring.security.xsuaa.flows.auto:false")
				.run((context) -> assertFalse(context.containsBean("xsuaaTokenFlows")));
	}

	@Test
	void autoConfigurationDisabledWhenNoClientIdIsGiven() {
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
		mt_properties.add("sap.security.services.xsuaa[0].certurl:https://domain.cert.auth.com");
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
					assertThat(context).doesNotHaveBean("defaultHttpClient");
					assertThat(context).hasBean("customHttpClient");
					assertThat(context).hasSingleBean(CloseableHttpClient.class);
				});
	}

	@Configuration
	static class UserConfiguration {

		@Bean
		public CloseableHttpClient customHttpClient() {
			return HttpClients.createDefault();
		}

		@Bean
		public XsuaaTokenFlows customTokenFlows() {
			return Mockito.mock(XsuaaTokenFlows.class);
		}
	}
}
