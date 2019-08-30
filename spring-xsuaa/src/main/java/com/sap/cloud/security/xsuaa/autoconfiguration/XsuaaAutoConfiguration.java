package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for default beans used by
 * the XSUAA client library.
 * <p>
 * Activates when there is a class of type {@link Jwt} on the classpath.
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

	private static final Logger logger = LoggerFactory.getLogger(XsuaaAutoConfiguration.class);

	@Configuration
	@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
	@ConditionalOnProperty(prefix = "spring.xsuaa", name = "multiple-bindings", havingValue = "false", matchIfMissing = true)
	public static class XsuaaServiceAutoConfiguration {

		@Bean
		@ConditionalOnMissingBean(XsuaaServiceConfiguration.class)
		public XsuaaServiceConfiguration xsuaaServiceConfiguration() {
			logger.info("auto-configures XsuaaServiceConfigurationDefault");
			return new XsuaaServiceConfigurationDefault();
		}
	}

	/**
	 * Creates a {@link RestOperations} instance if the application has not yet
	 * defined any yet.
	 *
	 * @return the {@link RestOperations} instance.
	 */
	@Bean
	@ConditionalOnMissingBean
	public RestOperations xsuaaRestOperations() {
		logger.info("auto-configures RestOperations for xsuaa requests)");
		return new RestTemplate();
	}

}