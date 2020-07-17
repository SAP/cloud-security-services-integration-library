package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import com.sap.cloud.security.cas.client.AdcServiceRequest;
import com.sap.cloud.security.cas.client.AdcServiceResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Testing the AdcService auto configuration.
 *
 * This test is based on the recommendations described in the official <a
 * href=https://docs.spring.io/autorepo/docs/spring-boot/current/reference/html/spring-boot-features.html#boot-features-test-autoconfig}>Spring
 * documentation</a>.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest
public class AutoConfigurationTest {

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(AdcServiceAutoConfiguration.class));

	@Test
	void adcService_isCreated() {
		contextRunner.run((context -> {
			assertThat(context).hasSingleBean(AdcService.class);
			assertThat(context).hasBean("adcService");
		}));
	}

	@Test
	void adcService_userConfigurationAvailable_backsOff() {
		contextRunner.withUserConfiguration(TestConfiguration.class).run((context -> {
			assertThat(context).hasBean("testAdcService");
			assertThat(context).hasSingleBean(AdcService.class);
		}));
	}

	@Configuration(proxyBeanMethods = false)
	static class TestConfiguration {
		@Bean
		AdcService testAdcService() {
			return new AdcService() {
				@Override
				public AdcServiceResponse isUserAuthorized(AdcServiceRequest adcServiceRequest) {
					return null;
				}

				@Override
				public boolean ping() {
					return false;
				}
			};
		}

	}

}
