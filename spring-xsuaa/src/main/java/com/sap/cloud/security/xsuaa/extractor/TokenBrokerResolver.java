package com.sap.cloud.security.xsuaa.extractor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cache.Cache;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

/**
 * Analyse authentication header and obtain token from UAA
 * 
 * For using this feature also in multi tenancy mode request-parameter {@code X-Identity-Zone-Subdomain} must be set or the AuthenticationInformationExtractor needs to be implemented).
 *
 */
public class TokenBrokerResolver implements BearerTokenResolver {

	private static final Log logger = LogFactory.getLog(TokenBrokerResolver.class);

	private static final String BASIC_CREDENTIAL = "basic";
	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final String OAUTH_TOKEN_PATH = "/oauth/token";

	private static final String BEARER_TYPE = "bearer";

	private XsuaaServiceConfiguration configuration;

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
	
	public TokenBrokerResolver(XsuaaServiceConfiguration configuration, Cache tokenCache, TokenBroker tokenBroker, AuthenticationInformationExtractor authenticationConfig) {
		this.configuration = configuration;
		this.tokenCache = tokenCache;
		this.tokenBroker = tokenBroker;
		this.uaaUrl = configuration.getUaaUrl();
		this.uaaDomain = configuration.getUaaDomain();
		this.authenticationConfig = authenticationConfig;
	}

	public  TokenBrokerResolver(XsuaaServiceConfiguration configuration, Cache tokenCache,AuthenticationMethod...authenticationMethods)
	{
		this(configuration,tokenCache, new UaaTokenBroker(),new DefaultAuthenticationInformationExtractor(authenticationMethods));
	}
	
	private void checkTypes(List<AuthenticationMethod> authenticationMethods) {
		if (authenticationMethods.contains(AuthenticationMethod.BASIC) && authenticationMethods.contains(AuthenticationMethod.CLIENT_CREDENTIALS)) {
			throw new IllegalArgumentException("Use either CLIENT_CREDENTIALS or BASIC");
		}
	}

	@Override
	public String resolve(HttpServletRequest request) {
		try {
			return extractToken(request);
		} catch (TokenBrokerException e) {
			logger.warn("Error obtaining token:" + e.getMessage(), e);
			return null;
		}
	}

	private String extractToken(HttpServletRequest request) throws TokenBrokerException {
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
			return token;
		}
		return null;
	}

	private String getBrokerToken(AuthenticationMethod credentialType, Enumeration<String> headers, String oauthTokenUrl) throws TokenBrokerException {
		while (headers.hasMoreElements()) {
			String header = headers.nextElement();
			switch (credentialType) {
			case OAUTH2:
				return extractCredential(BEARER_TYPE, header);
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
						String cacheKey = createSecureHash(oauthTokenUrl, clientId, clientSecret, credentialDetails[0], credentialDetails[1]);
						String storedToken = tokenCache.get(cacheKey, String.class);
						if (storedToken == null) {
							String token = tokenBroker.getAccessTokenFromPasswordCredentials(oauthTokenUrl, clientId, clientSecret, credentialDetails[0], credentialDetails[1]);
							tokenCache.put(cacheKey, token);
							return token;
						} else {
							return storedToken;
						}
					}
				}
				break;
			case CLIENT_CREDENTIALS:
				String clientCredential = extractCredential(BASIC_CREDENTIAL, header);
				if (clientCredential != null) {
					final String[] credentialDetails = obtainCredentialDetails(clientCredential);
					if (credentialDetails.length == 2) {
						String cacheKey = createSecureHash(oauthTokenUrl, credentialDetails[0], credentialDetails[1]);
						String storedToken = tokenCache.get(cacheKey, String.class);
						if (storedToken == null) {
							String token = tokenBroker.getAccessTokenFromClientCredentials(oauthTokenUrl, credentialDetails[0], credentialDetails[1]);
							tokenCache.put(cacheKey, token);
							return token;
						} else {
							return storedToken;
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
			return new String(Base64.getEncoder().encodeToString(messageDigest.digest()));
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
	public AuthenticationInformationExtractor getAuthenticationConfig() {
		return authenticationConfig;
	}

	public void setAuthenticationConfig(AuthenticationInformationExtractor authenticationConfig) {
		this.authenticationConfig = authenticationConfig;
	}
}
