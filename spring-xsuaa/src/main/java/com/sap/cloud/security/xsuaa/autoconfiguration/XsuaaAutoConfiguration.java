package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.VariableKeySetUriTokenDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.beans.factory.config.BeanDefinition.SCOPE_PROTOTYPE;

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
	 * Creates a {@link VariableKeySetUriTokenDecoder} instance based on a
	 * {@code NimbusJwtDecoderJwkSupport} implementation which is used by the
	 * {@link XsuaaTokenFlows} bean.
	 *
	 * @return the {@link VariableKeySetUriTokenDecoder} instance.
	 */
	@Bean
	@Scope(SCOPE_PROTOTYPE)
	@ConditionalOnMissingBean
	public VariableKeySetUriTokenDecoder xsuaaTokenDecoder() {
		logger.info("auto-configures NimbusTokenDecoder");
		return new NimbusTokenDecoder();
	}

}