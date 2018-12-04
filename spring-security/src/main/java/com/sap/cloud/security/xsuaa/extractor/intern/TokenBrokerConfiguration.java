/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor.intern;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthenticationInformationExtractor;
import com.sap.cloud.security.xsuaa.extractor.TokenBroker;
import com.sap.cloud.security.xsuaa.extractor.UaaTokenBroker;

@Configuration
public class TokenBrokerConfiguration {

	private static final String TOKEN_NAME = "token";

	@Bean
	public Cache tokenCache() {
		return new ConcurrentMapCache(TOKEN_NAME);
	}

	@Bean
	public TokenBroker tokenBroker() {
		return new UaaTokenBroker(tokenBrokerRestTemplate());
	}

	@Bean
	public RestTemplate tokenBrokerRestTemplate() {
		return new RestTemplate();
	}

	@Bean
	public AuthenticationInformationExtractor authenticationConfiguration() {
		return new DefaultAuthenticationInformationExtractor();
	}

}
