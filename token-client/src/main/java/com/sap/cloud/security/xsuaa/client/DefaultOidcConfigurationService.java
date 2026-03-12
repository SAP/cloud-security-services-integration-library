/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.client.HttpClientException;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpClientProvider;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import com.sap.cloud.security.xsuaa.util.UriUtil;
import jakarta.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <a href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest</a>
 */
public class DefaultOidcConfigurationService implements OidcConfigurationService {

  private final SecurityHttpClient httpClient;
  private static final Logger LOGGER =
      LoggerFactory.getLogger(DefaultOidcConfigurationService.class);
  private final DefaultTokenClientConfiguration config;

  public DefaultOidcConfigurationService() throws HttpClientException {
    this.httpClient = SecurityHttpClientProvider.createClient(null);
    this.config = DefaultTokenClientConfiguration.getInstance();
  }

  public DefaultOidcConfigurationService(final SecurityHttpClient httpClient) {
    Assertions.assertNotNull(httpClient, "httpClient is required");
    this.httpClient = httpClient;
    this.config = DefaultTokenClientConfiguration.getInstance();
  }

  /**
   * @deprecated Since version 4.0.0. Use {@link #DefaultOidcConfigurationService(SecurityHttpClient)} instead.
   *             For migration guidance, see the project documentation on custom HTTP clients.
   * @param httpClient the Apache HttpClient 4 instance
   */
  @Deprecated(since = "4.0.0", forRemoval = true)
  public DefaultOidcConfigurationService(final org.apache.http.impl.client.CloseableHttpClient httpClient) {
    this(new com.sap.cloud.security.client.ApacheHttpClient4Adapter(httpClient));
  }

  public static URI getDiscoveryEndpointUri(@Nonnull final String issuerUri) {
    final URI uri;
	if (issuerUri.startsWith("http://localhost") || issuerUri.startsWith("https://")) {
		uri = URI.create(issuerUri);
	} else if (issuerUri.startsWith("http://")) {
		// non-localhost http discovery endpoints are not supported
		return null;
	} else {
		uri = URI.create("https://" + issuerUri);
	}
	return UriUtil.expandPath(uri, DISCOVERY_ENDPOINT_DEFAULT);
}

  @Override
  public OAuth2ServiceEndpointsProvider retrieveEndpoints(@Nonnull final URI discoveryEndpointUri)
      throws OAuth2ServiceException {
    Assertions.assertNotNull(discoveryEndpointUri, "discoveryEndpointUri must not be null!");
    final String endpointsJson =
        executeRequest(
            discoveryEndpointUri, config.isRetryEnabled() ? config.getMaxRetryAttempts() : 0);
    return new OidcEndpointsProvider(endpointsJson);
  }

  private String executeRequest(final URI discoveryEndpointUri, final int attemptsLeft)
      throws OAuth2ServiceException {

    SecurityHttpRequest request = createHttpRequest(discoveryEndpointUri);
    LOGGER.debug(
        "Retrieving configured oidc endpoints: {} with headers {} and {} retries left",
        discoveryEndpointUri,
        request.getHeaders(),
        attemptsLeft);

    try {
      SecurityHttpResponse response = httpClient.execute(request);
      final int statusCode = response.getStatusCode();
      final String body = response.getBody();

      LOGGER.debug("Received statusCode {} from {}", statusCode, discoveryEndpointUri);

      if (statusCode == 200) {
        LOGGER.debug("Successfully retrieved oidc endpoints from {}.", discoveryEndpointUri);
        return body;
      } else if (attemptsLeft > 0 && config.getRetryStatusCodes().contains(statusCode)) {
        LOGGER.warn(
            "Request failed with status {} but is retryable. Retrying...", statusCode);
        pauseBeforeNextAttempt(config.getRetryDelayTime());
        return executeRequest(discoveryEndpointUri, attemptsLeft - 1);
      }

      throw OAuth2ServiceException.builder("Error retrieving configured oidc endpoints")
          .withStatusCode(statusCode)
          .withUri(discoveryEndpointUri)
          .withRequestHeaders(getHeadersAsStringArray(request.getHeaders()))
          .withResponseHeaders(getHeadersAsStringArray(response.getHeaders()))
          .withResponseBody(body)
          .build();

    } catch (final IOException e) {
      if (e instanceof final OAuth2ServiceException oAuth2Exception) {
        throw oAuth2Exception;
      } else {
        throw OAuth2ServiceException.builder(
                "Error retrieving configured oidc endpoints: " + e.getMessage())
            .withUri(discoveryEndpointUri)
            .withRequestHeaders(getHeadersAsStringArray(request.getHeaders()))
            .withResponseBody(e.getMessage())
            .build();
      }
    }
  }

  private SecurityHttpRequest createHttpRequest(final URI discoveryEndpointUri) {
    Map<String, String> headers = new HashMap<>();
    headers.put("User-Agent", HttpClientUtil.getUserAgent());

    return SecurityHttpRequest.newBuilder()
        .method("GET")
        .uri(discoveryEndpointUri)
        .headers(headers)
        .build();
  }

  private static String[] getHeadersAsStringArray(final Map<String, String> headers) {
    return headers != null
        ? headers.entrySet().stream()
            .map(e -> e.getKey() + ": " + e.getValue())
            .toArray(String[]::new)
        : new String[0];
  }

  private void pauseBeforeNextAttempt(final long sleepTime) {
    try {
      LOGGER.info("Retry again in {} ms", sleepTime);
      Thread.sleep(sleepTime);
    } catch (final InterruptedException e) {
      LOGGER.warn("Thread.sleep has been interrupted. Retry starts now.");
    }
  }

  static class OidcEndpointsProvider implements OAuth2ServiceEndpointsProvider {
    static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    static final String TOKEN_ENDPOINT = "token_endpoint";
    static final String JWKS_ENDPOINT = "jwks_uri";

    private final JSONObject jsonObject;

    OidcEndpointsProvider(final String jsonString) {
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
