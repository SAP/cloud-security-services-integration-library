/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa.security;

import com.sap.cloud.security.xsuaa.tokenflows.PasswordTokenFlow;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

/**
 * Resolves with an XSUAA user token from the configured service instance using the Basic HTTP credentials
 * in the request header to execute a {@link com.sap.cloud.security.token.GrantType#PASSWORD} grant type flow.
 * <p>
 * The user crendentials are expected to be contained in the {@link HttpHeaders#AUTHORIZATION} header field as BASE64-encoded username/password combination.
 * Optionally, a zone id may be specified via the 'X-Identity-Zone-Subdomain' header field.
 * <p>
 * For performance improvements, a pre-configured {@link Cache} may be supplied to limit the time between two token requests for the same principal.
 */
public class TokenBrokerResolver implements BearerTokenResolver {
	private static final Logger logger = LoggerFactory.getLogger(TokenBrokerResolver.class);
	public static final String BASIC_AUTHENTICATION_SCHEME = "Basic"; // prefix before BASE64 encoded username:password in Authorization header
	public static final String ZONE_ID_HEADER = "X-Identity-Zone-Subdomain"; // header for zone id
	private final XsuaaTokenFlows tokenFlows;
	private final Cache tokenCache;

	public TokenBrokerResolver(XsuaaTokenFlows tokenFlows, Cache tokenCache) {
		this.tokenFlows = tokenFlows;
		this.tokenCache = tokenCache;
	}

	@Override
	public String resolve(HttpServletRequest request) {
		try {
			return fetchToken(request);
		} catch (TokenFlowException e) {
			logger.warn("Error obtaining token: " + e.getMessage(), e);
			return null;
		}
	}

	private String fetchToken(HttpServletRequest request) throws TokenFlowException {
		String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authorization == null || !authorization.startsWith(BASIC_AUTHENTICATION_SCHEME)) {
			return null;
		}

		String encodedCredentials = authorization.substring(BASIC_AUTHENTICATION_SCHEME.length() + 1);
		UserCredentials credentials = decodeCredentials(encodedCredentials);
		if (credentials == null) {
			return null;
		}

		String zoneId = getZoneId(request).orElse(null);
		String cacheKey;
		if (zoneId != null) {
			cacheKey = createSecureHash(credentials.toString(), zoneId);
		} else {
			cacheKey = createSecureHash(credentials.toString());
		}

		String cachedToken = tokenCache.get(cacheKey, String.class);
		if (cachedToken != null) {
			logger.debug("returning access token for {} from cache.", cacheKey);
			return cachedToken;
		}

		PasswordTokenFlow tokenFlow = tokenFlows
				.passwordTokenFlow()
				.username(credentials.userName())
				.password(credentials.password)
				.subdomain(zoneId);
		String token = tokenFlow.execute().getAccessToken();

		tokenCache.put(cacheKey, token);
		return token;
	}

	@Nullable
	private UserCredentials decodeCredentials(String encodedCredentials) {
//		byte[] decodedBytes = Base64.getDecoder().decode(encodedCredentials.getBytes(StandardCharsets.UTF_8));
		final String decoded = new String(Base64.getDecoder().decode(encodedCredentials), StandardCharsets.UTF_8);
		final String[] parts = decoded.split(":", 2);

		if (parts.length == 2) {
			return new UserCredentials(parts[0], parts[1]);
		} else {
			return null;
		}
	}

	public Optional<String> getZoneId(HttpServletRequest request) {
		return Optional.ofNullable(request.getParameter(ZONE_ID_HEADER))
				.or(() -> Optional.ofNullable(request.getHeader(ZONE_ID_HEADER)))
				.or(Optional::empty);
	}

	 private static String createSecureHash(String... keys) {
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

	private record UserCredentials(String userName, String password) {}
}