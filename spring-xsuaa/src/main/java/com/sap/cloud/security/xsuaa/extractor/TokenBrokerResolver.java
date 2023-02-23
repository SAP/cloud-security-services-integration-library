/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.util.UriUtil;
import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Analyse authentication header and obtain token from UAA
 *
 * For using this feature also in multi tenancy mode request-parameter
 * {@code X-Identity-Zone-Subdomain} must be set (or the
 * AuthenticationInformationExtractor needs to be implemented).
 *
 * Token exchange between IAS and XSUAA is disabled by default. To enable IAS to
 * XSUAA token exchange set the environment variable IAS_XSUAA_XCHANGE_ENABLED
 * to any value except false.
 *
 */
public class TokenBrokerResolver implements BearerTokenResolver {

	private static final Logger logger = LoggerFactory.getLogger(TokenBrokerResolver.class);

	private static final String AUTH_BASIC_CREDENTIAL = HttpServletRequest.BASIC_AUTH;
	private static final String AUTH_HEADER = "Authorization";
	private static final String AUTH_BEARER = "bearer";

	private final XsuaaServiceConfiguration configuration;

	private final Cache tokenCache;
	private final OAuth2TokenService oAuth2TokenService;
	private AuthenticationInformationExtractor authenticationConfig;
	private IasXsuaaExchangeBroker iasXsuaaExchangeBroker;

	/**
	 * @param configuration
	 *            - Configuration properties from environment.
	 * @param tokenCache
	 *            - the Token-Cache.
	 * @param tokenService
	 *            - the {@link OAuth2TokenService} used to execute the final
	 *            request.
	 * @param authenticationConfig
	 *            - configured AuthenticationMethodConfiguration.
	 */
	public TokenBrokerResolver(XsuaaServiceConfiguration configuration, Cache tokenCache,
			OAuth2TokenService tokenService,
			AuthenticationInformationExtractor authenticationConfig) {
		this.configuration = configuration;
		this.tokenCache = tokenCache;
		this.oAuth2TokenService = tokenService;
		this.authenticationConfig = authenticationConfig;
		if (TokenUtil.isIasToXsuaaXchangeEnabled()) {
			this.iasXsuaaExchangeBroker = new IasXsuaaExchangeBroker(configuration, tokenService);
		}
	}

	@Override
	public String resolve(HttpServletRequest request) {
		try {
			return extractToken(request);
		} catch (TokenBrokerException | OAuth2ServiceException e) {
			logger.warn("Error obtaining token: " + e.getMessage(), e);
			return null;
		}
	}

	private String extractToken(HttpServletRequest request) throws TokenBrokerException, OAuth2ServiceException {
		List<AuthenticationMethod> authenticationMethods = authenticationConfig.getAuthenticationMethods(request);

		checkTypes(authenticationMethods);

		String oauthTokenUrl = getOAuthTokenUrl(request);

		ClientIdentity clientIdentity = configuration.getClientIdentity();

		for (AuthenticationMethod credentialType : authenticationMethods) {
			for (String authHeaderValue : Collections.list(request.getHeaders(AUTH_HEADER))) {
				String token = getBrokerToken(credentialType, authHeaderValue, oauthTokenUrl, clientIdentity);
				if (StringUtils.hasText(token)) {
					return token;
				}
			}
		}
		return null;
	}

	private void checkTypes(List<AuthenticationMethod> authenticationMethods) {
		if (authenticationMethods.contains(AuthenticationMethod.BASIC)
				&& authenticationMethods.contains(AuthenticationMethod.CLIENT_CREDENTIALS)) {
			throw new IllegalArgumentException("Use either CLIENT_CREDENTIALS or BASIC");
		}
	}

	private String getOAuthTokenUrl(HttpServletRequest request) {
		URI uaaUri = URI.create(configuration.getUaaUrl());
		URI certUri = configuration.getCertUrl();

		Optional<String> subdomainResult = authenticationConfig.getSubdomain(request);
		if (subdomainResult.isPresent()) {
			uaaUri = UriUtil.replaceSubdomain(uaaUri, subdomainResult.get());
			if(certUri != null) {
				certUri = UriUtil.replaceSubdomain(certUri, subdomainResult.get());
			}
		}

		XsuaaDefaultEndpoints tokenEndpoints = new XsuaaDefaultEndpoints(uaaUri.toString(), certUri != null ? certUri.toString() : null);
		return tokenEndpoints.getTokenEndpoint().toString();
	}

	private String getBrokerToken(AuthenticationMethod credentialType, String authHeaderValue,
			String oauthTokenUrl, ClientIdentity clientIdentity) throws TokenBrokerException, OAuth2ServiceException {
		switch (credentialType) {
		case OAUTH2:
			String oAuth2token = extractAuthenticationFromHeader(AUTH_BEARER, authHeaderValue);

			if (oAuth2token == null) {
				break;
			}
			if (TokenUtil.isIasToXsuaaXchangeEnabled()) {
				DecodedJwt decodedJwt = TokenUtil.decodeJwt(oAuth2token);
				if (!TokenUtil.isXsuaaToken(decodedJwt)) {
					try {
						return iasXsuaaExchangeBroker.doIasXsuaaXchange(decodedJwt);
					} catch (JSONException e) {
						logger.error("Couldn't decode the token: {}", e.getMessage());
					}
				}
			}
			return oAuth2token;
		case BASIC:
			String basicAuthHeader = extractAuthenticationFromHeader(AUTH_BASIC_CREDENTIAL, authHeaderValue);
			ClientCredentials userCredentialsFromHeader = getCredentialsFromBasicAuthorizationHeader(
					basicAuthHeader);
			if (userCredentialsFromHeader != null) {
				String cacheKey = createSecureHash(oauthTokenUrl, clientIdentity.toString(),
						userCredentialsFromHeader.toString());
				String cachedToken = tokenCache.get(cacheKey, String.class);
				if (cachedToken != null) {
					logger.debug("return (basic) access token for {} from cache", cacheKey);
					return cachedToken;
				} else {
					String token = oAuth2TokenService.retrieveAccessTokenViaPasswordGrant(URI.create(oauthTokenUrl),
							clientIdentity, userCredentialsFromHeader.getId(),
							userCredentialsFromHeader.getSecret(), null, null, false).getAccessToken();
					tokenCache.put(cacheKey, token);
					return token;
				}
			}
			break;
		case CLIENT_CREDENTIALS:
			String clientCredentialsAuthHeader = extractAuthenticationFromHeader(AUTH_BASIC_CREDENTIAL,
					authHeaderValue);
			ClientIdentity clientCredentialsFromHeader = getCredentialsFromBasicAuthorizationHeader(
					clientCredentialsAuthHeader);
			if (clientCredentialsFromHeader != null) {
				String cacheKey = createSecureHash(oauthTokenUrl, clientCredentialsFromHeader.toString());
				String cachedToken = tokenCache.get(cacheKey, String.class);
				if (cachedToken != null) {
					logger.debug("return (client-credentials) access token for {} from cache", cacheKey);
					return cachedToken;
				} else {
					String token = oAuth2TokenService.retrieveAccessTokenViaClientCredentialsGrant(
							URI.create(oauthTokenUrl), clientCredentialsFromHeader, null, null,
							null, false).getAccessToken();
					tokenCache.put(cacheKey, token);
					return token;
				}
			}
			break;
		default:
			return null;
		}
		return null;
	}

	@Nullable
	private ClientCredentials getCredentialsFromBasicAuthorizationHeader(@Nullable String basicAuthHeader) {
		if (basicAuthHeader == null) {
			return null;
		}
		byte[] decodedBytes = Base64.getDecoder().decode(basicAuthHeader.getBytes(StandardCharsets.UTF_8));
		final String pair = new String(decodedBytes, StandardCharsets.UTF_8);
		if (pair.contains(":")) {
			final String[] credentialDetails = pair.split(":", 2);
			if (credentialDetails.length == 2) {
				return new ClientCredentials(credentialDetails[0], credentialDetails[1]);
			}
		}
		return null;
	}

	private String createSecureHash(String... keys) {
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
			for (String k : keys) {
				messageDigest.update(k.getBytes(StandardCharsets.UTF_8));
			}
			byte[] hash = messageDigest.digest();
			return Base64.getEncoder().encodeToString(hash);
		} catch (NoSuchAlgorithmException e) {
			throw new SecurityException("No such Algorithm", e);
		}
	}

	private String extractAuthenticationFromHeader(String authenticationMethod, String authHeaderValue) {
		if ((authHeaderValue.toLowerCase().startsWith(authenticationMethod.toLowerCase()))) {
			String authorizationHeaderValue = authHeaderValue.substring(authenticationMethod.length()).trim();
			int index = authorizationHeaderValue.indexOf(',');
			if (index > 0) {
				authorizationHeaderValue = authorizationHeaderValue.substring(0, index);
			}
			return authorizationHeaderValue;
		}
		return null;
	}

	public AuthenticationInformationExtractor getAuthenticationConfig() {
		return authenticationConfig;
	}

	public void setAuthenticationConfig(AuthenticationInformationExtractor authenticationConfig) {
		this.authenticationConfig = authenticationConfig;
	}
}