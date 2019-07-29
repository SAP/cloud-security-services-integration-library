package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.DummyXsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.token.flows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.VariableKeySetUriTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlows;

import com.sap.cloud.security.xsuaa.token.flows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.VariableKeySetUriTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlows;
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
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

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
	public final void configures_xsuaaTokenFlows() {
		assertThat(context.getBean("xsuaaTokenFlows")).isNotNull();
		assertThat(context.getBean("xsuaaTokenFlows")).isInstanceOf(XsuaaTokenFlows.class);
		assertThat(context.getBean(XsuaaTokenFlows.class)).isNotNull();
	}

	@Test
	public final void configures_xsuaaTokenDecoder() {
		assertThat(context.getBean("xsuaaTokenDecoder")).isNotNull();
		assertThat(context.getBean("xsuaaTokenDecoder")).isInstanceOf(VariableKeySetUriTokenDecoder.class);
		assertThat(context.getBean(VariableKeySetUriTokenDecoder.class)).isNotNull();
	}

	@Test
	public final void configures_xsuaaTokenFlowRestTemplate() {
		assertThat(context.getBean("xsuaaTokenFlowRestTemplate")).isNotNull();
		assertThat(context.getBean("xsuaaTokenFlowRestTemplate")).isInstanceOf(RestTemplate.class);
		assertThat(context.getBean(RestTemplate.class)).isNotNull();
	}

	@Test
	public final void configures_xsuaaServiceConfiguration() {
		contextRunner.run((context) -> {
			assertThat(context).hasSingleBean(XsuaaServiceConfigurationDefault.class);
			assertThat(context).hasBean("xsuaaServiceConfiguration");
		});
	}

	@Test
	public final void configures_xsuaaServiceConfiguration_withProperties() {
		contextRunner
				.withPropertyValues("spring.xsuaa.auto:true")
				.withPropertyValues("spring.xsuaa.multiple-bindings:false").run((context) -> {
					assertThat(context.containsBean("xsuaaServiceConfiguration"), is(true));
					assertThat(context.getBean("xsuaaServiceConfiguration"),
							instanceOf(XsuaaServiceConfigurationDefault.class));
					assertThat(context.getBean(XsuaaServiceConfiguration.class), is(not(nullValue())));
				});
	}

	@Test
	public void autoConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.auto:false").run((context) -> {
			assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
		});
	}

	@Test
	public void serviceConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.multiple-bindings:true").run((context) -> {
			assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
		});
	}

	@Test
	public final void autoConfigurationInactive_if_noJwtOnClasspath() {
		contextRunner.withClassLoader(new FilteredClassLoader(Jwt.class)) // removes Jwt.class from classpath
				.run((context) -> {
					assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
					assertThat(context).doesNotHaveBean("xsuaaTokenFlows");
					assertThat(context).doesNotHaveBean("xsuaaTokenDecoder");
					assertThat(context).doesNotHaveBean("xsuaaTokenFlowRestTemplate");
				});
	}

	@Test
	public final void userConfigurationCanOverrideDefaultBeans() {
		contextRunner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertThat(context).hasSingleBean(DummyXsuaaServiceConfiguration.class);
					assertThat(context).doesNotHaveBean(XsuaaServiceConfigurationDefault.class);
					assertThat(context).hasBean("userDefinedServiceConfiguration");

					assertThat(context).hasSingleBean(XsuaaTokenFlows.class);
					assertThat(context).hasBean("userDefinedXsuaaTokenFlows");
					assertThat(context).doesNotHaveBean("xsuaaTokenFlows");

					assertThat(context).hasSingleBean(VariableKeySetUriTokenDecoder.class);
					assertThat(context).hasBean("userDefinedXsuaaTokenDecoder");
					assertThat(context).doesNotHaveBean("xsuaaTokenDecoder");

					assertThat(context).hasSingleBean(RestTemplate.class);
					assertThat(context).hasBean("userDefinedXsuaaTokenFlowRestTemplate");
					assertThat(context).doesNotHaveBean("xsuaaTokenFlowRestTemplate");
				});
	}

	@Configuration
	public static class UserConfiguration {

		@Bean
		public XsuaaServiceConfiguration userDefinedServiceConfiguration() {
			return new DummyXsuaaServiceConfiguration();
		}

		@Bean
		public VariableKeySetUriTokenDecoder userDefinedXsuaaTokenDecoder() {
			return new NimbusTokenDecoder();
		}

		@Bean
		public RestTemplate userDefinedXsuaaTokenFlowRestTemplate() {
			return new RestTemplate();
		}

		@Bean
		public XsuaaTokenFlows userDefinedXsuaaTokenFlows(RestTemplate restTemplate,
				VariableKeySetUriTokenDecoder decoder) {
			return new XsuaaTokenFlows(restTemplate, decoder);
		}
	}
}
