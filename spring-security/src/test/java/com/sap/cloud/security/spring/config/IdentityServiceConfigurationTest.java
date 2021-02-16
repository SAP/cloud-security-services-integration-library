package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.spring.config.IdentityServiceConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IdentityServiceConfigurationTest {

	private final ApplicationContextRunner runner = new ApplicationContextRunner();

	@EnableConfigurationProperties(IdentityServiceConfiguration.class)
	static class EnablePropertiesConfiguration {
	}

	@Test
	void configuresIdentityServiceConfiguration() {
		runner.withUserConfiguration(EnablePropertiesConfiguration.class)
				.withPropertyValues("sap.security.services.identity.url:http://localhost",
						"sap.security.services.identity.clientid:cid")
				.run(context -> {
					assertEquals("http://localhost",
							context.getBean(IdentityServiceConfiguration.class).getUrl().toString());
				});
	}
}
