/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;

import com.sap.cloud.security.xsuaa.token.service.TokenBrokerException;
import com.sap.cloud.security.xsuaa.util.JWTUtil;

/**
 *
 *
 */
@Configuration
public class TokenBrokerTestConfiguration {

	private static final String TOKEN_NAME = "token";

	@Bean
	public Cache tokenCache() {
		return new ConcurrentMapCache(TOKEN_NAME);
	}

	@Bean
	public TokenBroker tokenBroker() {
		return new TokenBroker() {
			@Override
			public DefaultOAuth2AccessToken getAccessTokenFromClientCredentials(String tokenURL, String clientId, String clientSecret) throws TokenBrokerException {
				try {
					return new DefaultOAuth2AccessToken(JWTUtil.createJWT(clientId));
				} catch (Exception e) {
					throw new TokenBrokerException("Error retrieving token", e);
				}
			}

			@Override
			public DefaultOAuth2AccessToken getAccessTokenFromPasswordCredentials(String tokenURL, String clientId, String clientSecret, String username, String password) throws TokenBrokerException {
				try {
					return new DefaultOAuth2AccessToken(JWTUtil.createJWT(clientId));
				} catch (Exception e) {
					throw new TokenBrokerException("Error retrieving token", e);
				}
			}
		};
	}

	@Bean
	public AuthenticationInformationExtractor authenticationConfiguration() {
		return new DefaultAuthenticationInformationExtractor();

	}

}
