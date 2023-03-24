/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import com.sap.cloud.security.xsuaa.util.UriUtil;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.json.JSONObject;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
 */
public class DefaultOidcConfigurationService implements OidcConfigurationService {

	private final CloseableHttpClient httpClient;

	public DefaultOidcConfigurationService() {
		this.httpClient = HttpClientFactory.create(null);
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

		HttpGet request = new HttpGet(discoveryEndpointUri);
		request.addHeader(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());

		String endpointsJson;
		try {
			endpointsJson = httpClient.execute(request, response -> {
				String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
				int statusCode = response.getCode();
				if(statusCode != HttpStatus.SC_OK) {
					throw OAuth2ServiceException.builder("Error retrieving configured oidc endpoints")
							.withUri(discoveryEndpointUri)
							.withStatusCode(statusCode)
							.withResponseBody(body)
							.build();
				}

				return body;
			});
		} catch (IOException e) {
			throw OAuth2ServiceException.builder("Error retrieving configured oidc endpoints: " + e.getMessage())
					.withUri(discoveryEndpointUri)
					.build();
		}

		return new OidcEndpointsProvider(endpointsJson);
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
