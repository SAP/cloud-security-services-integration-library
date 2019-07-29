package com.sap.cloud.security.xsuaa.token.flows;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_ADDITIONAL_AZ_ATTR;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A utilities class providing static functions required to build the XSUAA
 * token flow REST requests.
 */
class XsuaaTokenFlowsUtils {

	private static final String BASIC_AUTH_HEADER_FORMAT = "Basic %s";
	private static final String CREDENTIALS_FORMAT = "%s:%s";
	private static final String APPLICATION_JSON = "application/json";
	private static final String AUTHORIZATION_BEARER_TOKEN_FORMAT = "Bearer %s";

	/**
	 * Adds the {@code  Accept: application/json} header to the set of headers.
	 * 
	 * @param headers
	 *            - the set of headers to add the header to.
	 */
	static void addAcceptHeader(HttpHeaders headers) {
		headers.add(HttpHeaders.ACCEPT, APPLICATION_JSON);
	}

	/**
	 * Adds the {@code  Authorization: Basic <credentials>} header to the set of
	 * headers.
	 * 
	 * @param headers
	 *            - the set of headers to add the header to.
	 * @param clientId
	 *            - the client ID used for authentication.
	 * @param clientSecret
	 *            - the client secret used for authentication.
	 */
	static void addBasicAuthHeader(HttpHeaders headers, String clientId, String clientSecret) {
		String credentials = String.format(CREDENTIALS_FORMAT, clientId, clientSecret);
		String base64Creds = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
		headers.add(HttpHeaders.AUTHORIZATION, String.format(BASIC_AUTH_HEADER_FORMAT, base64Creds));
	}

	/**
	 * Adds the {@code  Authorization: Bearer <token>} header to the set of headers.
	 * 
	 * @param headers
	 *            - the set of headers to add the header to.
	 * @param token
	 *            - the token which should be part of the header.
	 */
	static void addAuthorizationBearerHeader(HttpHeaders headers, Jwt token) {
		headers.add(HttpHeaders.AUTHORIZATION, String.format(AUTHORIZATION_BEARER_TOKEN_FORMAT, token.getTokenValue()));
	}

	/**
	 * Builds the additional authorities claim of the JWT. Returns null, if the
	 * request does not have any additional authorities set.
	 * 
	 * @param request
	 *            the request.
	 * @return the additional authorities claims or null, if the request has no
	 *         additional authorities set.
	 * @throws TokenFlowException
	 */
	static String buildAuthorities(XsuaaTokenFlowRequest request) throws TokenFlowException {

		if (request.getAdditionalAuthorizationAttributes() == null) {
			return null;
		}

		try {
			Map<String, String> additionalAuthorities = request.getAdditionalAuthorizationAttributes();
			return buildAdditionalAuthoritiesJson(additionalAuthorities);
		} catch (JsonProcessingException e) {
			throw new TokenFlowException(
					"Error mapping additional authorization attributes to JSON. See root cause exception. ", e);
		}
	}

	static String buildAdditionalAuthoritiesJson(Map<String, String> additionalAuthorities)
			throws JsonProcessingException {
		Map<String, Object> additionalAuthorizationAttributes = new HashMap<>();
		additionalAuthorizationAttributes.put(CLAIM_ADDITIONAL_AZ_ATTR, additionalAuthorities);

		ObjectMapper mapper = new ObjectMapper();
		String additionalAuthorizationAttributesJson = mapper.writeValueAsString(additionalAuthorizationAttributes);
		return additionalAuthorizationAttributesJson;
	}
}
