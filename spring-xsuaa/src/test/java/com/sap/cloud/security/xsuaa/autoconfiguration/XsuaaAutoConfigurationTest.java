/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.DummyXsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import org.apache.commons.io.IOUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;


import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@SpringBootTest(classes = { XsuaaAutoConfiguration.class, DummyXsuaaServiceConfiguration.class })
class XsuaaAutoConfigurationTest {

	// create an ApplicationContextRunner that will create a context with the
	// configuration under test.
	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(XsuaaAutoConfiguration.class));
	private static String cert;
	private static String key;

	@Autowired
	private ApplicationContext context;

	@BeforeAll
	static void setup() throws IOException {
		cert = IOUtils.resourceToString("/certificate.txt", StandardCharsets.UTF_8);
		key = IOUtils.resourceToString("/key.txt", StandardCharsets.UTF_8);
	}

	@Test
	void configures_xsuaaServiceConfiguration() {
		contextRunner.withClassLoader(new FilteredClassLoader(CloseableHttpClient.class))
				.run((context) -> {
					assertThat(context).hasSingleBean(XsuaaServiceConfigurationDefault.class);
					assertThat(context).hasBean("xsuaaServiceConfiguration");
				});
	}

	@Test
	void configures_K8sXsuaaServiceConfiguration() {
		contextRunner
				.withPropertyValues("KUBERNETES_SERVICE_HOST", "1.0.0.0")
				.run((context) -> {
					assertThat(context).hasSingleBean(XsuaaServiceConfiguration.class);
					assertThat(context).hasBean("xsuaaServiceConfigurationK8s");
				});

	}

	@Test
	void configures_xsuaaRestTemplate() {
		assertThat(context.getBean("xsuaaRestOperations")).isNotNull();
		assertThat(context.getBean("xsuaaRestOperations")).isInstanceOf(RestOperations.class);
		assertThat(context.getBean(RestOperations.class)).isNotNull();
	}

	@Test
	void configures_xsuaaMtlsRestTemplate() {
		contextRunner
				.withPropertyValues("spring.xsuaa.flows.auto:true")
				.withPropertyValues("xsuaa.credential-type:x509")
				.withPropertyValues("xsuaa.clientid:client")
				.withPropertyValues("xsuaa.certificate:" + cert)
				.withPropertyValues("xsuaa.key:" + key)
				.withPropertyValues("xsuaa.certurl:https://domain.cert.authentication.sap.com")
				.run((context) -> {
					assertThat(context).hasSingleBean(RestOperations.class);
					assertThat(context).hasBean("xsuaaMtlsRestOperations");
				});
	}

	@Test
	void configures_xsuaaServiceConfiguration_withProperties() {
		contextRunner.withClassLoader(new FilteredClassLoader(CloseableHttpClient.class))
				.withPropertyValues("spring.xsuaa.auto:true")
				.withPropertyValues("spring.xsuaa.disable-default-property-source:false")
				.withPropertyValues("spring.xsuaa.multiple-bindings:false").run((context) -> {
					assertThat(context.containsBean("xsuaaServiceConfiguration"), is(true));
					assertThat(context.getBean("xsuaaServiceConfiguration"),
							instanceOf(XsuaaServiceConfigurationDefault.class));
					assertThat(context.getBean(XsuaaServiceConfiguration.class), is(not(nullValue())));

					assertThat(context).hasSingleBean(RestTemplate.class);
				});
	}

	@Test
	void autoConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.auto:false").run((context) -> {
			assertThat(context).doesNotHaveBean(RestTemplate.class);
			assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
		});
	}

	@Test
	void serviceConfigurationDisabledByMultipleBindingsProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.multiple-bindings:true")
				.run((context) -> assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration"));
	}

	@Test
	void serviceConfigurationDisabledByDisableDefaultPropertySourceProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.disable-default-property-source:true")
				.run((context) -> assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration"));
	}

	@Test
	void autoConfigurationInactive_if_noJwtOnClasspath() {
		contextRunner.withClassLoader(new FilteredClassLoader(Jwt.class)) // removes Jwt.class from classpath
				.run((context) -> {
					assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
					assertThat(context).doesNotHaveBean("xsuaaTokenDecoder");
					assertThat(context).doesNotHaveBean("xsuaaRestOperations");
				});
	}

	@Test
	void userConfiguration_overrides_defaultBeans() {
		contextRunner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertThat(context).hasSingleBean(DummyXsuaaServiceConfiguration.class);
					assertThat(context).doesNotHaveBean(XsuaaServiceConfigurationDefault.class);
					assertThat(context).hasBean("userDefinedServiceConfiguration");

					assertThat(context).hasSingleBean(RestTemplate.class);
					assertThat(context).hasBean("userDefinedXsuaaRestOperations");
					assertThat(context).doesNotHaveBean("xsuaaRestOperations");
				});
	}

	@Test
	void userConfiguration_overrides_defaultMtlsRestTemplate() {
		contextRunner
				.withUserConfiguration(UserConfiguration.class)
				.withPropertyValues("xsuaa.credential-type:x509")
				.run((context) -> {
					assertThat(context.getEnvironment().getProperty("xsuaa.credential-type")).isEqualTo("x509");
					assertThat(context).hasSingleBean(RestOperations.class);
					assertThat(context).doesNotHaveBean("xsuaaMtlsRestOperations");
					assertThat(context).doesNotHaveBean("xsuaaRestOperations");
					assertThat(context).hasBean("userDefinedXsuaaRestOperations");
				});
	}

	@Configuration
	public static class UserConfiguration {
		@Bean
		public RestTemplate userDefinedXsuaaRestOperations() {
			return new RestTemplate();
		}

		@Bean
		public XsuaaServiceConfiguration userDefinedServiceConfiguration() {
			return new DummyXsuaaServiceConfiguration();
		}
	}
}