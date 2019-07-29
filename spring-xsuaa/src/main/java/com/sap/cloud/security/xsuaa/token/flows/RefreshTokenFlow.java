package com.sap.cloud.security.xsuaa.token.flows;

import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.addAcceptHeader;
import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.addBasicAuthHeader;

import java.net.URI;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A refresh token flow builder. <br>
 * Applications can use this flow exchange a given refresh token for a
 * (refreshed) JWT token.
 */
public class RefreshTokenFlow {

	private static final String ACCESS_TOKEN = "access_token";
	private static final String REFRESH_TOKEN = "refresh_token";
	private static final String GRANT_TYPE = "grant_type";

	private RestTemplate restTemplate;
	private XsuaaTokenFlowRequest request;
	private String refreshToken;
	private VariableKeySetUriTokenDecoder tokenDecoder;

	/**
	 * Creates a new instance.
	 * 
	 * @param restTemplate
	 *            - the {@link RestTemplate} used to execute the final request.
	 * @param xsuaaBaseUri
	 *            - the base URI of XSUAA. Based on the base URI the tokenEndpoint,
	 *            authorize and key set URI will be derived.
	 */
	RefreshTokenFlow(RestTemplate restTemplate, VariableKeySetUriTokenDecoder tokenDecoder, URI xsuaaBaseUri) {
		Assert.notNull(restTemplate, "RestTemplate must not be null.");
		Assert.notNull(tokenDecoder, "TokenDecoder must not be null.");
		Assert.notNull(xsuaaBaseUri, "XSUAA base URI must not be null.");

		URI tokenEndpoint = UriComponentsBuilder.fromUri(xsuaaBaseUri).path("/oauth/token").build().toUri();
		URI authorizeEndpoint = UriComponentsBuilder.fromUri(xsuaaBaseUri).path("/oauth/authorize").build().toUri();
		URI keySetEndpoint = UriComponentsBuilder.fromUri(xsuaaBaseUri).path("/token_keys").build().toUri();

		this.restTemplate = restTemplate;
		this.tokenDecoder = tokenDecoder;
		this.request = new XsuaaTokenFlowRequest(tokenEndpoint, authorizeEndpoint, keySetEndpoint);
	}

	/**
	 * Creates a new instance.
	 * 
	 * @param restTemplate
	 *            - the {@link RestTemplate} used to execute the final request.
	 * @param tokenEndpoint
	 *            - the token endpoint URI.
	 * @param authorizeEndpoint
	 *            - the authorize endpoint URI.
	 * @param keySetEndpoint
	 *            - the key set endpoint URI.
	 */
	RefreshTokenFlow(RestTemplate restTemplate, VariableKeySetUriTokenDecoder tokenDecoder, URI tokenEndpoint,
			URI authorizeEndpoint, URI keySetEndpoint) {
		Assert.notNull(restTemplate, "RestTemplate must not be null.");
		Assert.notNull(tokenDecoder, "TokenDecoder must not be null.");
		Assert.notNull(tokenEndpoint, "Token endpoint URI must not be null.");
		Assert.notNull(authorizeEndpoint, "Authorize endpoint URI must not be null.");
		Assert.notNull(keySetEndpoint, "Key set endpoint URI must not be null.");

		this.restTemplate = restTemplate;
		this.tokenDecoder = tokenDecoder;
		this.request = new XsuaaTokenFlowRequest(tokenEndpoint, authorizeEndpoint, keySetEndpoint);
	}

	/**
	 * Sets the mandatory refresh token to be exchanged for a (refreshed) JWT.
	 * 
	 * @param refreshToken
	 *            - the refresh token to be exchanged for a JWT.
	 * @return this builder object.
	 */
	public RefreshTokenFlow refreshToken(String refreshToken) {
		Assert.notNull(refreshToken, "RefreshToken must not be null.");
		this.refreshToken = refreshToken;
		return this;
	}

	/**
	 * The OAuth 2.0 client ID used to authenticate to XSUAA.
	 * 
	 * @param clientId
	 *            - the OAuth 2.0 client ID.
	 * @return this builder object.
	 */
	public RefreshTokenFlow client(String clientId) {
		request.setClientId(clientId);
		return this;
	}

	/**
	 * The OAuth 2.0 client secret used to authenticate to XSUAA.
	 * 
	 * @param clientSecret
	 *            - the OAuth 2.0 client secret.
	 * @return this builder object.
	 */
	public RefreshTokenFlow secret(String clientSecret) {
		request.setClientSecret(clientSecret);
		return this;
	}

	/**
	 * Executes the refresh token flow against XSUAA.
	 * 
	 * @return the refreshed JWT token or an exception in case the token could not
	 *         be refreshed.
	 * @throws TokenFlowException
	 *             in case of an error during the flow, or when the token cannot be
	 *             refreshed.
	 */
	public Jwt execute() throws TokenFlowException {

		checkRequest(request);

		return refreshToken(refreshToken, request);
	}

	/**
	 * Checks that all mandatory fields of the token flow request have been set.
	 * Otherwise throws an exception.
	 * 
	 * @param request
	 *            - the request to check.
	 * @throws TokenFlowException
	 *             in case not all mandatory fields of the token flow request have
	 *             been set.
	 */
	private void checkRequest(XsuaaTokenFlowRequest request) throws TokenFlowException {

		if (refreshToken == null) {
			throw new TokenFlowException(
					"Refresh token not set. Make sure to have called the refreshToken() method on RefreshTokenFlow builder.");
		}

		if (!request.isValid()) {
			throw new TokenFlowException(
					"Refresh token flow request is not valid. Make sure all mandatory fields are set.");
		}
	}

	/**
	 * Refreshes the token based on the given {@code refreshToken} instance.
	 * 
	 * @param refreshToken
	 *            - the (opaque) refresh token.
	 * @param request
	 *            - the token flow request to execute.
	 * @return the JWT received in exchange for the refresh token.
	 * @throws TokenFlowException
	 *             in case of an error in the flow.
	 */
	private Jwt refreshToken(String refreshToken, XsuaaTokenFlowRequest request) throws TokenFlowException {

		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(request.getTokenEndpoint());
		builder.queryParam(GRANT_TYPE, REFRESH_TOKEN)
				.queryParam(REFRESH_TOKEN, refreshToken);

		HttpHeaders headers = createRefreshTokenHeaders(request);

		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> responseEntity = restTemplate.postForEntity(requestUri, requestEntity, Map.class);

		HttpStatus responseStatusCode = responseEntity.getStatusCode();

		if (responseStatusCode == HttpStatus.UNAUTHORIZED) {
			throw new TokenFlowException(String.format(
					"Error refreshing token. Received status code %s. Call to XSUAA was not successful (grant_type: refresh_token). Client credentials invalid.",
					responseStatusCode));
		}

		if (responseStatusCode != HttpStatus.OK) {
			throw new TokenFlowException(String.format(
					"Error refreshing token. Received status code %s. Call to XSUAA was not successful (grant_type: refresh_token).",
					responseStatusCode));
		}

		String encodedJwtToken = responseEntity.getBody().get(ACCESS_TOKEN).toString();

		return decode(encodedJwtToken, request.getKeySetEndpoint());
	}

	/**
	 * Creates the set of headers required for the refresh token flow.
	 * 
	 * @param request
	 *            - the token flow request.
	 * @return the set of HTTP headers.
	 */
	private HttpHeaders createRefreshTokenHeaders(XsuaaTokenFlowRequest request) {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		addBasicAuthHeader(headers, request.getClientId(), request.getClientSecret());
		return headers;
	}

	/**
	 * Decodes the received encoded JWT token.
	 * 
	 * @param encodedToken
	 *            the encoded JWT token value.
	 * @return the decoded JWT instance.
	 * @throws TokenFlowException
	 *             in case of a decoding error.
	 */
	private Jwt decode(String encodedToken, URI keySetEndpoint) throws TokenFlowException {

		tokenDecoder.setJwksURI(keySetEndpoint);
		// validation is not required by the one who retrieves the token,
		// but by the one who receives it (e.g. the service it is sent to).
		// Hence, here we only decode, but do not validate.
		// decoder.setJwtValidator(new
		// DelegatingOAuth2TokenValidator<>(tokenValidators));
		Jwt jwt = tokenDecoder.decode(encodedToken);
		return jwt;
	}
}
