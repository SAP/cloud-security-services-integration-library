/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import java.net.URI;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.client.*;

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
			public OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(@Nonnull URI tokenEndpointUri,
					@Nonnull ClientIdentity clientIdentity, @Nullable String zoneId, @Nullable String subdomain,
					@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
					throws OAuth2ServiceException {
				try {
					return new OAuth2TokenResponse("token_" + clientIdentity.getId(), 100, null);
				} catch (Exception e) {
					throw new OAuth2ServiceException("Error retrieving token: " + e.getMessage());
				}
			}

			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(URI tokenEndpointUri,
					ClientIdentity clientIdentity, String refreshToken, @Nullable String subdomain,
					boolean disableCacheForRequest) {
				return null;
			}

			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(URI tokenEndpointUri,
					ClientIdentity clientIdentity, String username, String password, @Nullable String subdomain,
					@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
					throws OAuth2ServiceException {
				try {
					if ("https://mydomain.auth.com/oauth/token".equals(tokenEndpointUri.toString())) {
						if ("myuser".equals(username) && "mypass".equals(password)
								&& "myclient!t1".equals(clientIdentity.getId())
								&& "top.secret".equals(clientIdentity.getSecret()))
							return new OAuth2TokenResponse("token_pwd", 100, null);
					}
					if ("https://other.auth.com/oauth/token".equals(tokenEndpointUri.toString())) {
						if ("myuser".equals(username) && "mypass".equals(password)
								&& "myclient!t1".equals(clientIdentity.getId())
								&& "top.secret".equals(clientIdentity.getSecret()))
							return new OAuth2TokenResponse("other_token_pwd", 100, null);
					}
					throw new Exception("wrong credentials");
				} catch (Exception e) {
					throw new OAuth2ServiceException("Error retrieving token: " + e.getMessage());
				}
			}

			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
					ClientIdentity clientIdentity, String token, @Nullable String subdomain,
					@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest) {
				return new OAuth2TokenResponse(XSUAA_TOKEN, 100, null);
			}

			@Override
			public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
					ClientIdentity clientIdentity, @Nonnull String token,
					@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest,
					@Nonnull String xZidHeader) {
				return new OAuth2TokenResponse(XSUAA_TOKEN, 100, null);
			}
		};
	}

	@Bean
	public AuthenticationInformationExtractor authenticationConfiguration() {
		return new DefaultAuthenticationInformationExtractor();

	}

}
