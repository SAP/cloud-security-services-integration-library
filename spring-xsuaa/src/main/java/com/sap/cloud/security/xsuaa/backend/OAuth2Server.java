package com.sap.cloud.security.xsuaa.backend;

import com.sap.cloud.security.xsuaa.OAuthServerEndpointsProvider;
import com.sap.cloud.security.xsuaa.token.flows.TokenFlowException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.addAcceptHeader;
import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.addBasicAuthHeader;

public class OAuth2Server {

	private RestTemplate restTemplate;
	private OAuthServerEndpointsProvider oAuthServerEndpointsProvider;

	private static final String ACCESS_TOKEN = "access_token";
	private static final String GRANT_TYPE = "grant_type";
	private static final String CLIENT_CREDENTIALS = "client_credentials";
	private static final String AUTHORITIES = "authorities";

	public OAuth2Server(RestTemplate restTemplate, OAuthServerEndpointsProvider oAuthServerEndpointsProvider) {
		this.restTemplate = restTemplate;
		this.oAuthServerEndpointsProvider = oAuthServerEndpointsProvider;
	}

	/**
	 * Requests the client credentials token from XSUAA.
	 *
	 * @return the JWT token returned by XSUAA.
	 * @throws TokenFlowException in case of an error during the flow.
	 */
	public String requestTechnicalUserToken(Map<String, String> additionalAuthorizationAttributes, String clientId,
			String clientSecret) throws TokenFlowException {

		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(oAuthServerEndpointsProvider.getTokenEndpoint());

		// add grant type to URI
		builder.queryParam(GRANT_TYPE, CLIENT_CREDENTIALS);

		String authorities = buildAuthorities(additionalAuthorizationAttributes); // returns JSON!
		if (authorities != null) {
			builder.queryParam(AUTHORITIES, authorities); // places JSON inside the URI !?!
		}

		HttpHeaders headers = createHeadersForTechnicalUserTokenExchange(clientId, clientSecret);

		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();

		@SuppressWarnings("rawtypes")
		try {
			ResponseEntity<Map> responseEntity = restTemplate.postForEntity(requestUri, requestEntity, Map.class);
		} catch (HttpClientErrorException ex) {
			HttpStatus responseStatusCode = ex.getStatusCode();
			if (responseStatusCode == HttpStatus.UNAUTHORIZED) {
				throw new TokenFlowException(String.format(
						"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful (grant_type: client_credentials). Client credentials invalid.",
						responseStatusCode));
			}

			if (!responseStatusCode.is2xxSuccessful()) {
				throw new TokenFlowException(String.format(
						"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful (grant_type: client_credentials).",
						responseStatusCode));
			}
		}
		return responseEntity.getBody().get(ACCESS_TOKEN).toString();
	}

	/**
	 * Creates a set of headers required for the token exchange with XSUAA.
	 *
	 * @return the set of headers.
	 */
	private HttpHeaders createHeadersForTechnicalUserTokenExchange(String clientId, String clientSecret) {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		addBasicAuthHeader(headers, clientId, clientSecret);
		return headers;
	}
}
