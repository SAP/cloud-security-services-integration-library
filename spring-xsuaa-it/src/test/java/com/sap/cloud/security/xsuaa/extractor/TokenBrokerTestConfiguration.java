package com.sap.cloud.security.xsuaa.extractor;

import java.net.URI;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;

/**
 *
 *
 */
@Configuration
public class TokenBrokerTestConfiguration {

	private static final String TOKEN_NAME = "token";
	private static final String XSUAA_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHRfYXR0ciI6eyJlbmhhbmNlciI6IlhTVUFBIn19._cocFCqqATDXx6eBUoF22W9F8VwUVYY59XdLGdEDFso";

	@Bean
	public Cache tokenCache() {
		return new ConcurrentMapCache(TOKEN_NAME);
	}

	@Bean
	public OAuth2TokenService tokenBroker() {
		return new OAuth2TokenService() {
			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(URI tokenEndpointUri,
					ClientCredentials clientCredentials, @Nullable String subdomain,
					@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
					throws OAuth2ServiceException {
				try {
					return new OAuth2TokenResponse("token_cc", 100, null);
				} catch (Exception e) {
					throw new OAuth2ServiceException("Error retrieving token: " + e.getMessage());
				}
			}

			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaUserTokenGrant(URI tokenEndpointUri,
					ClientCredentials clientCredentials, String token, @Nullable String subdomain,
					@Nullable Map<String, String> optionalParameters)
					throws OAuth2ServiceException {
				return null;
			}

			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(URI tokenEndpointUri,
					ClientCredentials clientCredentials, String refreshToken, @Nullable String subdomain,
					boolean disableCacheForRequest)
					throws OAuth2ServiceException {
				return null;
			}

			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(URI tokenEndpointUri,
					ClientCredentials clientCredentials, String username, String password, @Nullable String subdomain,
					@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
					throws OAuth2ServiceException {
				try {
					if ("https://mydomain.auth.com/oauth/token".equals(tokenEndpointUri.toString())) {
						if ("myuser".equals(username) && "mypass".equals(password)
								&& "myclient!t1".equals(clientCredentials.getId())
								&& "top.secret".equals(clientCredentials.getSecret()))
							return new OAuth2TokenResponse("token_pwd", 100, null);
					}
					if ("https://other.auth.com/oauth/token".equals(tokenEndpointUri.toString())) {
						if ("myuser".equals(username) && "mypass".equals(password)
								&& "myclient!t1".equals(clientCredentials.getId())
								&& "top.secret".equals(clientCredentials.getSecret()))
							return new OAuth2TokenResponse("other_token_pwd", 100, null);
					}
					throw new Exception("wrong credentials");
				} catch (Exception e) {
					throw new OAuth2ServiceException("Error retrieving token: " + e.getMessage());
				}
			}

			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
					ClientCredentials clientCredentials, String token, @Nullable String subdomain,
					@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
					throws OAuth2ServiceException {
				return new OAuth2TokenResponse(XSUAA_TOKEN, 100, null);
			}

			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
					ClientCredentials clientCredentials, @Nonnull String token,
					@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest,
					@Nonnull String xZidHeader)
					throws OAuth2ServiceException {
				return new OAuth2TokenResponse(XSUAA_TOKEN, 100, null);
			}
		};
	}

	@Bean
	public AuthenticationInformationExtractor authenticationConfiguration() {
		return new DefaultAuthenticationInformationExtractor();

	}

}
