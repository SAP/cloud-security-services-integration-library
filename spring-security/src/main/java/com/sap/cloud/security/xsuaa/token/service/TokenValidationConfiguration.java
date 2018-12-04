package com.sap.cloud.security.xsuaa.token.service;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.ServiceConfiguration;
import com.sap.cloud.security.xsuaa.api.TokenValidator;

@Configuration
public class TokenValidationConfiguration {

	@Autowired
	private ServiceConfiguration configuration;

	@Bean
	public TokenValidator onlineTokenValidator() {
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
			@Override
			// Ignore 400 (400 = invalid token)
			public void handleError(ClientHttpResponse response) throws IOException {
				if (response.getRawStatusCode() != 400) {
					super.handleError(response);
				}
			}
		});

		OnlineTokenValidator onlineTokenValidator = new OnlineTokenValidator(configuration, restTemplate);
		return onlineTokenValidator;
	}

	@Bean
	public TokenValidator offlineTokenValidator() {
		RestTemplate restTemplate = new RestTemplate();
		return new OfflineTokenValidator(configuration, restTemplate, tokenKeyCache());
	}

	@Bean
	public Cache tokenKeyCache() {
		return new ConcurrentMapCache("tokenKeyCache");
	}
}
