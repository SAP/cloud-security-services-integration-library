package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for default beans used by
 * the XSUAA client library.
 * <p>
 * Activates when there is a bean of type {@link Jwt} configured in the context.
 *
 * <p>
 * can be disabled
 * with @EnableAutoConfiguration(exclude={XsuaaAutoConfiguration.class}) or with
 * property spring.xsuaa.auto = false
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@ConditionalOnProperty(prefix = "spring.xsuaa", name = "auto", havingValue = "true", matchIfMissing = true)
public class XsuaaAutoConfiguration {

	@Configuration
	@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
	@ConditionalOnProperty(prefix = "spring.xsuaa", name = "multiple-bindings", havingValue = "false", matchIfMissing = true)
	public static class XsuaaServiceAutoConfiguration {

		@Bean
		@ConditionalOnMissingBean(XsuaaServiceConfiguration.class)
		public XsuaaServiceConfiguration xsuaaServiceConfiguration() {
			return new XsuaaServiceConfigurationDefault();
		}
	}
}
