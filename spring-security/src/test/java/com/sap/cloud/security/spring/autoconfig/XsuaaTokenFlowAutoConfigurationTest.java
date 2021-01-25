package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;


import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class XsuaaTokenFlowAutoConfigurationTest {

	private final List<String> properties = new ArrayList<>();
	private ApplicationContextRunner runner;

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
		runner.run(context -> {
			assertNotNull(context.getBean("xsuaaTokenFlows", XsuaaTokenFlows.class));
		});
	}

	@Test
	void autoConfigurationActiveInclProperties() {
		runner.withPropertyValues("sap.spring.security.xsuaa.flows.auto:true").run((context) -> {
			assertNotNull(context.getBean("xsuaaTokenFlows", XsuaaTokenFlows.class));
		});
	}

	@Test
	void autoConfigurationDisabledByProperty() {
		runner.withPropertyValues("sap.spring.security.xsuaa.flows.auto:false").run((context) -> {
			assertFalse(context.containsBean("xsuaaTokenFlows"));
		});
	}

	@Test
	void autoConfigurationDisabledForMultipleXsuaaServices() {
		List<String> mt_properties = new ArrayList<>();
		WebApplicationContextRunner mt_runner;

		mt_properties.add("sap.security.services.xsuaa[0].url:http://localhost");
		mt_properties.add("sap.security.services.xsuaa[0].clientid:cid");
		mt_properties.add("sap.security.services.xsuaa[0].clientsecret:pwd");

		mt_runner = new WebApplicationContextRunner()
				.withPropertyValues(mt_properties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class,
						XsuaaTokenFlowAutoConfiguration.class));

		mt_runner.run(context -> {
			assertNotNull(context.getBean("xsuaaTokenFlows", XsuaaTokenFlows.class));
		});
	}

	@Test
	void autoConfigurationUsesTokenFlowsForMultipleXsuaaServicesAsPrimary() {
		List<String> mt_properties = new ArrayList<>();
		WebApplicationContextRunner mt_runner;

		mt_properties.addAll(properties);
		mt_properties.add("sap.security.services.xsuaa[0].url:http://localhost");
		mt_properties.add("sap.security.services.xsuaa[0].clientid:cid");
		mt_properties.add("sap.security.services.xsuaa[0].clientsecret:pwd");
		mt_properties.add("sap.security.services.xsuaa[1].clientid:cid");

		mt_runner = new WebApplicationContextRunner()
				.withPropertyValues(mt_properties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class,
						XsuaaTokenFlowAutoConfiguration.class));

		mt_runner.run(context -> {
			assertTrue(context.containsBean("xsuaaTokenFlows"));
		});
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
