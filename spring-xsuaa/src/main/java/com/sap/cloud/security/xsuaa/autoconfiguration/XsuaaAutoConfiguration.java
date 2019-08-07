package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory;
import com.sap.cloud.security.xsuaa.backend.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.token.flows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.VariableKeySetUriTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.sap.cloud.security.xsuaa.tokenflows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.VariableKeySetUriTokenDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

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
	 * Creates a new {@link XsuaaTokenFlows} bean that applications
	 * can auto-wire into their controllers to perform a programmatic
	 * token flow exchange.
	 *  
	 * @param restTemplate - the {@link RestTemplate} to use for the token flow exchange.
	 * @param decoder - the decoder used for the tokens retrieved via the token flows.
	 * @return the {@link XsuaaTokenFlows} API.
	 */
	@Bean
    @ConditionalOnMissingBean
    public XsuaaTokenFlows xsuaaTokenFlows(RestTemplate restTemplate, VariableKeySetUriTokenDecoder decoder) {
        return new XsuaaTokenFlows(restTemplate, decoder);
    }
    
    /**
     * Creates a {@link VariableKeySetUriTokenDecoder} instance 
     * based on a {@code NimbusJwtDecoderJwkSupport}
     * implementation which is used by the {@link XsuaaTokenFlows} bean.
     * @return the {@link VariableKeySetUriTokenDecoder} instance.
     */
    @Bean
    @ConditionalOnMissingBean
    public VariableKeySetUriTokenDecoder xsuaaTokenDecoder() {
        return new NimbusTokenDecoder();
    }

    /**
     * Creates a {@link RestTemplate} instance
     * if the application has not yet defined any
     * yet.
     * @return the {@link RestTemplate} instance.
     */
    @Bean
    @ConditionalOnMissingBean
    public RestTemplate xsuaaTokenFlowRestTemplate() {
        return new RestTemplate();
    }
	@ConditionalOnMissingBean
	@ConditionalOnBean(XsuaaServiceConfiguration.class)
	public XsuaaTokenFlows xsuaaTokenFlows(RestTemplate restTemplate, VariableKeySetUriTokenDecoder decoder, XsuaaServiceConfiguration serviceConfiguration) {
		return new XsuaaTokenFlows(restTemplate, decoder, new XsuaaDefaultEndpoints(URI.create(serviceConfiguration.getUaaUrl())));
	}

	/**
	 * Creates a {@link VariableKeySetUriTokenDecoder} instance based on a
	 * {@code NimbusJwtDecoderJwkSupport} implementation which is used by the
	 * {@link XsuaaTokenFlows} bean.
	 *
	 * @return the {@link VariableKeySetUriTokenDecoder} instance.
	 */
	@Bean
	@ConditionalOnMissingBean
	public VariableKeySetUriTokenDecoder xsuaaTokenDecoder() {
		return new NimbusTokenDecoder();
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
		return new RestTemplate();
	}
}
