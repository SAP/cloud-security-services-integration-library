package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for default beans used by
 * the XSUAA client library.
 * <p>
 * Activates when there is a class of type {@link Jwt} on the classpath.
 *
 * <p>
 * can be disabled
 * with @EnableAutoConfiguration(exclude={XsuaaTokenFlowAutoConfiguration.class})
 * or with property spring.xsuaa.auto = false
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@ConditionalOnProperty(prefix = "spring.xsuaa.flows", name = "auto", havingValue = "true", matchIfMissing = true)
public class XsuaaTokenFlowAutoConfiguration {

	private static final Logger logger = LoggerFactory.getLogger(XsuaaAutoConfiguration.class);

	/**
	 * Creates a new {@link XsuaaTokenFlows} bean that applications can auto-wire
	 * into their controllers to perform a programmatic token flow exchange.
	 *
	 * @param restTemplate
	 *            - the {@link RestTemplate} to use for the token flow exchange.
	 * @return the {@link XsuaaTokenFlows} API.
	 */
	@Bean
	@ConditionalOnBean({ XsuaaServiceConfiguration.class })
	@ConditionalOnMissingBean
	public XsuaaTokenFlows xsuaaTokenFlows(RestTemplate restTemplate, XsuaaServiceConfiguration serviceConfiguration) {
		logger.info("auto-configures XsuaaTokenFlows");
		return new XsuaaTokenFlows(restTemplate, new XsuaaDefaultEndpoints(serviceConfiguration.getUaaUrl()));
	}

	/**
	 * Creates a {@link RestTemplate} instance if the application has not yet
	 * defined any yet.
	 *
	 * @return the {@link RestTemplate} instance.
	 */
	@Bean
	@ConditionalOnMissingBean
	public RestTemplate xsuaaTokenFlowRestTemplate() {
		logger.info("auto-configures RestTemplate (for xsuaa token flows)");
		return new RestTemplate();
	}
}
