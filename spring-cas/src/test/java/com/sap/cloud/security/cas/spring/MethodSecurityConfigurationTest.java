package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = { XsuaaAutoConfiguration.class, AdcServiceConfiguration.class, MethodSecurityConfiguration.class})
public class MethodSecurityConfigurationTest {

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(AdcServiceConfiguration.class, MethodSecurityConfiguration.class));

	@Test
	void hasExpressionHandler() {
		contextRunner.run((context -> {
			assertThat(context).hasBean("expressionHandler");
		}));
	}

	@Test
	void withXsuaaAutoConfiguration_hasExpressionHandlerXsuaa() {
		contextRunner.withUserConfiguration(XsuaaAutoConfiguration.class).run((context -> {
			assertThat(context).hasBean("expressionHandlerXsuaa");
		}));
	}
}
