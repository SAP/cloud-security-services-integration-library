/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock.autoconfiguration;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import com.sap.cloud.security.xsuaa.mock.MockXsuaaServiceConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = { XsuaaMockAutoConfiguration.class })
public class XsuaaMockAutoConfigurationTest {

	// create an ApplicationContextRunner that will create a context with the
	// configuration under test.
	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withPropertyValues("mockxsuaaserver.url:http://localhost:12345")
			.withConfiguration(AutoConfigurations.of(XsuaaAutoConfiguration.class, XsuaaMockAutoConfiguration.class));

	@Autowired
	private ApplicationContext context;

	@Test
	public final void autoConfigurationActive() {
		contextRunner.run((context) -> {
			assertThat(context.containsBean("xsuaaMockServiceConfiguration"), is(true));
			assertThat(context.getBean("xsuaaMockServiceConfiguration"),
					instanceOf(MockXsuaaServiceConfiguration.class));
			assertThat(context.getBean("xsuaaServiceConfiguration"),
					instanceOf(XsuaaServiceConfigurationDefault.class));
			assertThat(context.getBean(XsuaaServiceConfiguration.class),
					instanceOf(MockXsuaaServiceConfiguration.class));
		});
	}

	@Test
	public final void autoConfigurationActiveInclProperties() {
		contextRunner
				.withPropertyValues("spring.xsuaa.mock.auto:true").run((context) -> {
					assertThat(context.containsBean("xsuaaMockServiceConfiguration"), is(true));
					assertThat(context.getBean(XsuaaServiceConfiguration.class),
							instanceOf(MockXsuaaServiceConfiguration.class));
				});
	}

	@Test
	public void autoConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.mock.auto:false").run((context) -> {
			assertThat(context.containsBean("xsuaaMockServiceConfiguration"), is(false));
			assertThat(context.getBean(XsuaaServiceConfiguration.class),
					instanceOf(XsuaaServiceConfigurationDefault.class));
		});
	}

	@Test
	public void autoConfigurationDisabledWhenNoMockWebServerRunning() {
		ApplicationContextRunner contextRunner = new ApplicationContextRunner()
				.withConfiguration(
						AutoConfigurations.of(XsuaaAutoConfiguration.class, XsuaaMockAutoConfiguration.class));

		contextRunner.withPropertyValues("spring.xsuaa.mock.auto:false").run((context) -> {
			assertThat(context.containsBean("xsuaaMockServiceConfiguration"), is(false));
			assertThat(context.getBean(XsuaaServiceConfiguration.class),
					instanceOf(XsuaaServiceConfigurationDefault.class));
		});
	}

	@Test
	public final void autoConfigurationWithoutJwtOnClasspathInactive() {
		contextRunner.withClassLoader(new FilteredClassLoader(Jwt.class)) // removes Jwt.class from classpath
				.run((context) -> {
					assertThat(context.containsBean("xsuaaServiceConfiguration"), is(false));
				});
	}

	@Test
	public final void userConfigurationCanOverrideDefaultBeans() {
		contextRunner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertThat(context.containsBean("xsuaaMockServiceConfiguration"), is(false));
					assertThat(context.containsBean("customServiceConfiguration"), is(true));
					assertThat(context.getBean(XsuaaServiceConfiguration.class),
							instanceOf(CustomXsuaaConfiguration.class));
				});
	}

	@Configuration
	public static class UserConfiguration {

		@Bean
		public MockXsuaaServiceConfiguration customServiceConfiguration() {
			return new CustomXsuaaConfiguration();
		}
	}

	static class CustomXsuaaConfiguration extends MockXsuaaServiceConfiguration {

	}

}
