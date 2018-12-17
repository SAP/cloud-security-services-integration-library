/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
			public String getAccessTokenFromClientCredentials(String tokenURL, String clientId, String clientSecret)
					throws TokenBrokerException {
				try {
					return "token_cc"; // new JWTUtil.createJWT(clientId);
				} catch (Exception e) {
					throw new TokenBrokerException("Error retrieving token", e);
				}
			}

			@Override
			public String getAccessTokenFromPasswordCredentials(String tokenURL, String clientId, String clientSecret,
					String username, String password) throws TokenBrokerException {
				try {
					if ("https://mydomain.auth.com/oauth/token".equals(tokenURL)) {
						if ("myuser".equals(username) && "mypass".equals(password) && "myclient!t1".equals(clientId)
								&& "top.secret".equals(clientSecret))
							return "token_pwd";
					} 
					if ("https://other.auth.com/oauth/token".equals(tokenURL)) {
						if ("myuser".equals(username) && "mypass".equals(password) && "myclient!t1".equals(clientId)
								&& "top.secret".equals(clientSecret))
							return "other_token_pwd";
					}
					throw new Exception("wrong credentials");
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
