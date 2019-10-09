package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.util.UriUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

public class XsuaaOAuth2TokenService implements OAuth2TokenService {

	private final RestOperations restOperations;
	private static Logger logger = LoggerFactory.getLogger(XsuaaOAuth2TokenService.class);
	private final HttpHeadersFactory httpHeadersFactory;

	public XsuaaOAuth2TokenService(@NonNull RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations is required");
		this.restOperations = restOperations;
		this.httpHeadersFactory = new HttpHeadersFactory();
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(@NonNull URI tokenEndpointUri,
			@NonNull ClientCredentials clientCredentials,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		Assert.notNull(tokenEndpointUri, "tokenEndpointUri is required");
		Assert.notNull(clientCredentials, "clientCredentials is required");

		// build parameters
		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
		addClientCredentialsToParameters(clientCredentials, parameters);
		if (optionalParameters != null) {
			optionalParameters.forEach(parameters::putIfAbsent);
		}

		// build header
		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpointUri, subdomain), headers, copyIntoForm(parameters));
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaUserTokenGrant(@NonNull URI tokenEndpointUri,
			@NonNull ClientCredentials clientCredentials, @NonNull String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		Assert.notNull(tokenEndpointUri, "tokenEndpointUri is required");
		Assert.notNull(clientCredentials, "clientCredentials is required");
		Assert.notNull(token, "token is required");

		// build parameters
		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_USER_TOKEN);
		parameters.put(PARAMETER_CLIENT_ID, clientCredentials.getId());
		if (optionalParameters != null) {
			optionalParameters.forEach(parameters::putIfAbsent);
		}

		// build header
		HttpHeaders headers = httpHeadersFactory.createWithAuthorizationBearerHeader(token);

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpointUri, subdomain), headers, copyIntoForm(parameters));
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(@NonNull URI tokenEndpointUri,
			@NonNull ClientCredentials clientCredentials,
			@NonNull String refreshToken, String subdomain) throws OAuth2ServiceException {
		Assert.notNull(tokenEndpointUri, "tokenEndpointUri is required");
		Assert.notNull(clientCredentials, "clientCredentials is required");
		Assert.notNull(refreshToken, "refreshToken is required");

		// build parameters
		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
		parameters.put(REFRESH_TOKEN, refreshToken);
		addClientCredentialsToParameters(clientCredentials, parameters);

		// build header
		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpointUri, subdomain), headers, copyIntoForm(parameters));
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(@NonNull URI tokenEndpoint,
			@NonNull ClientCredentials clientCredentials, @NonNull String username, @NonNull String password,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		Assert.notNull(tokenEndpoint, "tokenEndpoint is required");
		Assert.notNull(clientCredentials, "clientCredentials are required");
		Assert.notNull(username, "username is required");
		Assert.notNull(password, "password is required");

		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
		parameters.put(USERNAME, username);
		parameters.put(PASSWORD, password);
		addClientCredentialsToParameters(clientCredentials, parameters);

		if (optionalParameters != null) {
			optionalParameters.forEach(parameters::putIfAbsent);
		}

		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpoint, subdomain), headers, copyIntoForm(parameters));
	}

	private OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			MultiValueMap<String, String> parameters) throws OAuth2ServiceException {

		// Create URI
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);
		URI requestUri = builder.build().encode().toUri();

		org.springframework.http.HttpHeaders springHeaders = new org.springframework.http.HttpHeaders();
		headers.getHeaders().forEach(h -> springHeaders.add(h.getName(), h.getValue()));

		// Create entity
		HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(parameters, springHeaders);

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> responseEntity = null;
		try {
			responseEntity = restOperations.postForEntity(requestUri, requestEntity, Map.class);
		} catch (HttpClientErrorException ex) {
			String warningMsg = String.format(
					"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful: %s",
					ex.getStatusCode(), ex.getResponseBodyAsString());
			throw new OAuth2ServiceException(warningMsg);
		} catch (HttpServerErrorException ex) {
			String warningMsg = String.format("Server error while obtaining access token from XSUAA (%s): %s",
					ex.getStatusCode(), ex.getResponseBodyAsString());
			logger.error(warningMsg, ex);
			throw new OAuth2ServiceException(warningMsg);
		}

		@SuppressWarnings("unchecked")
		Map<String, String> accessTokenMap = responseEntity.getBody();
		logger.debug("Request Access Token: {}", responseEntity.getBody());

		String accessToken = accessTokenMap.get(ACCESS_TOKEN);
		long expiresIn = Long.parseLong(String.valueOf(accessTokenMap.get(EXPIRES_IN)));
		String refreshToken = accessTokenMap.get(REFRESH_TOKEN);
		return new OAuth2TokenResponse(accessToken, expiresIn, refreshToken);
	}

	/**
	 * Creates a copy of the given map or an new empty map of type MultiValueMap.
	 *
	 * @return a new @link{MultiValueMap} that contains all entries of the optional
	 *         map.
	 */
	private static MultiValueMap<String, String> copyIntoForm(Map<String, String> parameters) {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap();
		if (parameters != null) {
			parameters.forEach(formData::add);
		}
		return formData;
	}

	private void addClientCredentialsToParameters(ClientCredentials clientCredentials,
			Map<String, String> parameters) {
		parameters.put(CLIENT_ID, clientCredentials.getId());
		parameters.put(CLIENT_SECRET, clientCredentials.getSecret());
	}

}
