package com.sap.cloud.security.xsuaa.client;

import javax.annotation.Nonnull;

import java.io.IOException;
import java.net.URI;

import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import com.sap.cloud.security.xsuaa.util.UriUtil;

/**
 * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
 */
public class DefaultOidcConfigurationService implements OidcConfigurationService {

	static final Logger logger = LoggerFactory.getLogger(DefaultOidcConfigurationService.class);
	private final CloseableHttpClient httpClient;

	public DefaultOidcConfigurationService() {
		this.httpClient = HttpClients.createDefault();
	}

	public DefaultOidcConfigurationService(CloseableHttpClient httpClient) {
		Assertions.assertNotNull(httpClient, "httpClient is required");
		this.httpClient = httpClient;
	}

	public static URI getDiscoveryEndpointUri(@Nonnull String issuerUri) {
		// to support existing IAS applications
		URI uri = URI.create(issuerUri.startsWith("http") ? issuerUri : "https://" + issuerUri);
		return UriUtil.expandPath(uri, DISCOVERY_ENDPOINT_DEFAULT);
	}

	@Override
	public OAuth2ServiceEndpointsProvider retrieveEndpoints(@Nonnull URI discoveryEndpointUri)
			throws OAuth2ServiceException {
		Assertions.assertNotNull(discoveryEndpointUri, "discoveryEndpointUri must not be null!");

		HttpUriRequest request = new HttpGet(discoveryEndpointUri);
		try (CloseableHttpResponse response = httpClient.execute(request)) {
			String bodyAsString = HttpClientUtil.extractResponseBodyAsString(response);
			int statusCode = response.getStatusLine().getStatusCode();
			return handleResponse(bodyAsString, statusCode);
		} catch (IOException e) {
			throw new OAuth2ServiceException(
					"Error retrieving configured oidc endpoints from " + discoveryEndpointUri + " : " + e.getMessage());
		}
	}

	private OAuth2ServiceEndpointsProvider handleResponse(String bodyAsString, int statusCode)
			throws OAuth2ServiceException {
		if (statusCode == HttpStatus.SC_OK) {
			return new OidcEndpointsProvider(bodyAsString);
		} else {
			throw OAuth2ServiceException
					.createWithStatusCodeAndResponseBody("Error retrieving configured oidc endpoints", statusCode,
							bodyAsString);
		}
	}

	static class OidcEndpointsProvider implements OAuth2ServiceEndpointsProvider {
		static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
		static final String TOKEN_ENDPOINT = "token_endpoint";
		static final String JWKS_ENDPOINT = "jwks_uri";

		private JSONObject jsonObject;

		OidcEndpointsProvider(String jsonString) {
			jsonObject = new JSONObject(jsonString);
		}

		@Override
		public URI getTokenEndpoint() {
			return URI.create(jsonObject.getString(TOKEN_ENDPOINT));
		}

		@Override
		public URI getAuthorizeEndpoint() {
			return URI.create(jsonObject.getString(AUTHORIZATION_ENDPOINT));
		}

		@Override
		public URI getJwksUri() {
			return URI.create(jsonObject.getString(JWKS_ENDPOINT));
		}
	}
}
