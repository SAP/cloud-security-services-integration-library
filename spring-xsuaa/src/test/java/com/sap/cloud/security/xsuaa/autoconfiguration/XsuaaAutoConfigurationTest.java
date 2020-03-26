package com.sap.cloud.security.xsuaa.autoconfiguration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

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
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.DummyXsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = { XsuaaAutoConfiguration.class, DummyXsuaaServiceConfiguration.class })
public class XsuaaAutoConfigurationTest {

	// create an ApplicationContextRunner that will create a context with the
	// configuration under test.
	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(XsuaaAutoConfiguration.class));

	@Autowired
	private ApplicationContext context;

	@Test
	public void configures_xsuaaServiceConfiguration() {
		contextRunner.run((context) -> {
			assertThat(context).hasSingleBean(XsuaaServiceConfigurationDefault.class);
			assertThat(context).hasBean("xsuaaServiceConfiguration");
		});
	}

	@Test
	public void configures_xsuaaRestTemplate() {
		assertThat(context.getBean("xsuaaRestOperations")).isNotNull();
		assertThat(context.getBean("xsuaaRestOperations")).isInstanceOf(RestOperations.class);
		assertThat(context.getBean(RestOperations.class)).isNotNull();
	}

	@Test
	public void configures_xsuaaServiceConfiguration_withProperties() {
		contextRunner
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
	public void autoConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.auto:false").run((context) -> {
			assertThat(context).doesNotHaveBean(RestTemplate.class);
			assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
		});
	}

	@Test
	public void serviceConfigurationDisabledByMultipleBindingsProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.multiple-bindings:true").run((context) -> {
			assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
		});
	}

	@Test
	public void serviceConfigurationDisabledByDisableDefaultPropertySourceProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.disable-default-property-source:true").run((context) -> {
			assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
		});
	}

	@Test
	public void autoConfigurationInactive_if_noJwtOnClasspath() {
		contextRunner.withClassLoader(new FilteredClassLoader(Jwt.class)) // removes Jwt.class from classpath
				.run((context) -> {
					assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
					assertThat(context).doesNotHaveBean("xsuaaTokenDecoder");
					assertThat(context).doesNotHaveBean("xsuaaRestOperations");
				});
	}

	@Test
	public void userConfigurationCanOverrideDefaultBeans() {
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