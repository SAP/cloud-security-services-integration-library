package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
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
import org.springframework.web.client.RestOperations;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for default beans used by
 * the XSUAA client library.
 * <p>
 * Activates when there is a class of type {@link XsuaaTokenFlows} on the
 * classpath.
 *
 * <p>
 * can be disabled
 * with @EnableAutoConfiguration(exclude={XsuaaTokenFlowAutoConfiguration.class})
 * or with property spring.xsuaa.flows.auto = false
 */
@Configuration
@ConditionalOnClass(XsuaaTokenFlows.class)
@ConditionalOnProperty(prefix = "spring.xsuaa.flows", name = "auto", havingValue = "true", matchIfMissing = true)
public class XsuaaTokenFlowAutoConfiguration {

	private static final Logger logger = LoggerFactory.getLogger(XsuaaTokenFlowAutoConfiguration.class);

	/**
	 * Creates a new {@link XsuaaTokenFlows} bean that applications can auto-wire
	 * into their controllers to perform a programmatic token flow exchange.
	 *
	 * @param restOperations
	 *            - the {@link RestOperations} to use for the token flow exchange.
	 * @param serviceConfiguration
	 *            - the {@link XsuaaServiceConfiguration} to configure the Xsuaa
	 *            Base Url.
	 * @return the {@link XsuaaTokenFlows} API.
	 */
	@Bean
	@ConditionalOnBean({ XsuaaServiceConfiguration.class, RestOperations.class })
	@ConditionalOnMissingBean
	public XsuaaTokenFlows xsuaaTokenFlows(RestOperations restOperations,
			XsuaaServiceConfiguration serviceConfiguration) {
		logger.info("auto-configures XsuaaTokenFlows");
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(serviceConfiguration.getUaaUrl());
		ClientCredentials clientCredentials = new ClientCredentials(serviceConfiguration.getClientId(),
				serviceConfiguration.getClientSecret());
		return new XsuaaTokenFlows(restOperations, endpointsProvider, clientCredentials);
	}
}
