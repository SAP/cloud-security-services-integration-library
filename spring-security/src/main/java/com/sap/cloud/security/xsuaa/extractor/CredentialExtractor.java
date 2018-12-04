package com.sap.cloud.security.xsuaa.extractor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cache.Cache;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;

import com.sap.cloud.security.xsuaa.ServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.service.TokenBrokerException;
import com.sap.cloud.security.xsuaa.token.service.TokenUrlUtils;

/**
 * Analyse authentication header and obtain token from UAA
 * 
 * For using this feature also in multi tenancy mode request-parameter {@code X-Identity-Zone-Subdomain} must be set or the AuthenticationInformationExtractor needs to be implemented).
 *
 */
public class CredentialExtractor implements TokenExtractor {

	private static final Log logger = LogFactory.getLog(CredentialExtractor.class);

	private static final String BASIC_CREDENTIAL = "basic";
	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final String OAUTH_TOKEN_PATH = "/oauth/token";

	private ServiceConfiguration configuration;

	private Cache tokenCache;
	private TokenBroker tokenBroker;
	private String uaaUrl;
	private String uaaDomain;
	private AuthenticationInformationExtractor authenticationConfig;

	/**
	 * @param configuration
	 *            Configuration properties from environment
	 * @param tokenCache
	 *            Token-Cache
	 * @param tokenBroker
	 *            Token-Broker for accessing the UAA
	 * @param authenticationConfig
	 *            configured AuthenticationMethodConfiguration
	 */
	public CredentialExtractor(ServiceConfiguration configuration, Cache tokenCache, TokenBroker tokenBroker, AuthenticationInformationExtractor authenticationConfig) {
		this.configuration = configuration;
		this.tokenCache = tokenCache;
		this.tokenBroker = tokenBroker;
		this.uaaUrl = configuration.getUaaUrl();
		this.uaaDomain = configuration.getUaadomain();
		this.authenticationConfig = authenticationConfig;
	}

	private void checkTypes(List<AuthenticationMethod> authenticationMethods) {
		if (authenticationMethods.contains(AuthenticationMethod.BASIC) && authenticationMethods.contains(AuthenticationMethod.CLIENT_CREDENTIALS)) {
			throw new IllegalArgumentException("Use either CLIENT_CREDENTIALS or BASIC");
		}
	}

	@Override
	public Authentication extract(HttpServletRequest request) {
		try {
			return extractToken(request);
		} catch (TokenBrokerException e) {
			logger.warn("Error obtaining token:" + e.getMessage(), e);
			return null;
		}
	}

	private Authentication extractToken(HttpServletRequest request) throws TokenBrokerException {
		List<AuthenticationMethod> authenticationMethods = authenticationConfig.getAuthenticationMethods(request);

		checkTypes(authenticationMethods);

		Optional<String> subdomainResult = authenticationConfig.getSubdomain(request);
		String oauthTokenUrl;
		if (subdomainResult.isPresent()) {
			oauthTokenUrl = TokenUrlUtils.getMultiTenancyUrl(OAUTH_TOKEN_PATH, uaaUrl, uaaDomain, subdomainResult.get());
		} else {
			oauthTokenUrl = TokenUrlUtils.getOauthTokenUrl(OAUTH_TOKEN_PATH, uaaUrl, uaaDomain);
		}

		for (AuthenticationMethod credentialType : authenticationMethods) {
			Enumeration<String> headers = request.getHeaders(AUTHORIZATION_HEADER);
			String token = getBrokerToken(credentialType, headers, oauthTokenUrl);
			if (token != null) {
				HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request) {
					@Override
					public Enumeration<String> getHeaders(String name) {
						if (AUTHORIZATION_HEADER.equals(name)) {
							return Collections.enumeration(Collections.singletonList(OAuth2AccessToken.BEARER_TYPE + " " + token));
						}
						return super.getHeaders(name);
					}
				};
				return new BearerTokenExtractor().extract(wrapper);
			}
		}
		return null;
	}

	private String getBrokerToken(AuthenticationMethod credentialType, Enumeration<String> headers, String oauthTokenUrl) throws TokenBrokerException {
		while (headers.hasMoreElements()) {
			String header = headers.nextElement();
			switch (credentialType) {
			case OAUTH2:
				return extractCredential(OAuth2AccessToken.BEARER_TYPE, header);
			case BASIC:
				String clientId = configuration.getClientId();
				String clientSecret = configuration.getClientSecret();
				if (clientId == null) {
					throw new TokenBrokerException("Missing clientId");
				}
				if (clientSecret == null) {
					throw new TokenBrokerException("Missing client secret");
				}
				String basicCredential = extractCredential(BASIC_CREDENTIAL, header);
				if (basicCredential != null) {
					final String[] credentialDetails = obtainCredentialDetails(basicCredential);
					if (credentialDetails.length == 2) {
						String cacheKey = createSecureHash(clientId, clientSecret, credentialDetails[0], credentialDetails[1]);
						DefaultOAuth2AccessToken storedToken = tokenCache.get(cacheKey, DefaultOAuth2AccessToken.class);
						if (storedToken == null) {
							DefaultOAuth2AccessToken token = tokenBroker.getAccessTokenFromPasswordCredentials(oauthTokenUrl, clientId, clientSecret, credentialDetails[0], credentialDetails[1]);
							tokenCache.put(cacheKey, token);
							return token.getValue();
						} else {
							return storedToken.getValue();
						}
					}
				}
				break;
			case CLIENT_CREDENTIALS:
				String clientCredential = extractCredential(BASIC_CREDENTIAL, header);
				if (clientCredential != null) {
					final String[] credentialDetails = obtainCredentialDetails(clientCredential);
					if (credentialDetails.length == 2) {
						String cacheKey = createSecureHash(credentialDetails[0], credentialDetails[1]);
						DefaultOAuth2AccessToken storedToken = tokenCache.get(cacheKey, DefaultOAuth2AccessToken.class);
						if (storedToken == null) {
							DefaultOAuth2AccessToken token = tokenBroker.getAccessTokenFromClientCredentials(oauthTokenUrl, credentialDetails[0], credentialDetails[1]);
							tokenCache.put(cacheKey, token);
							return token.getValue();
						} else {
							return storedToken.getValue();
						}
					}
				}
				break;
			default:
				return null;
			}
		}
		return null;
	}

	private String[] obtainCredentialDetails(String basicCredential) {
		byte[] decodedBytes = Base64.getDecoder().decode(basicCredential.getBytes(StandardCharsets.UTF_8));
		final String pair = new String(decodedBytes, StandardCharsets.UTF_8);
		if (pair.contains(":")) {
			final String[] credentialDetails = pair.split(":", 2);
			return credentialDetails;
		}
		return new String[0];
	}

	private String createSecureHash(String... keys) {
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(Arrays.toString(keys).getBytes(StandardCharsets.UTF_8));
			return new String(messageDigest.digest());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("No such Algorithm", e);
		}
	}

	private String extractCredential(String credentialName, String httpHeader) {
		if ((httpHeader.toLowerCase().startsWith(credentialName.toLowerCase()))) {
			String authorizationHeaderValue = httpHeader.substring(credentialName.length()).trim();
			int index = authorizationHeaderValue.indexOf(',');
			if (index > 0) {
				authorizationHeaderValue = authorizationHeaderValue.substring(0, index);
			}
			return authorizationHeaderValue;
		}
		return null;
	}

}
