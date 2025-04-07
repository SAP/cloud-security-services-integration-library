/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import com.sap.cloud.security.xsuaa.util.UriUtil;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.annotation.Nonnull;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <a href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest</a>
 */
public class DefaultOidcConfigurationService implements OidcConfigurationService {

  private final CloseableHttpClient httpClient;
  private static final Logger LOGGER =
      LoggerFactory.getLogger(DefaultOidcConfigurationService.class);
  private final DefaultTokenClientConfiguration config;

  public DefaultOidcConfigurationService() {
    this.httpClient = HttpClientFactory.create(null);
    this.config = DefaultTokenClientConfiguration.getInstance();
  }

  public DefaultOidcConfigurationService(final CloseableHttpClient httpClient) {
    Assertions.assertNotNull(httpClient, "httpClient is required");
    this.httpClient = httpClient;
    this.config = DefaultTokenClientConfiguration.getInstance();
  }

  public static URI getDiscoveryEndpointUri(@Nonnull final String issuerUri) {
    // to support existing IAS applications
    final URI uri =
        URI.create(
            issuerUri.startsWith("http://localhost") || issuerUri.startsWith("https://")
                ? issuerUri
                : "https://" + issuerUri);
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
    final HttpGet httpGet = new HttpGet(discoveryEndpointUri);
    httpGet.addHeader(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
    LOGGER.debug(
        "Retrieving configured oidc endpoints: {} with headers {} and {} retries left",
        discoveryEndpointUri,
        httpGet.getAllHeaders(),
        attemptsLeft);
    try {
      return httpClient.execute(
          httpGet,
          response -> {
            final int statusCode = response.getStatusLine().getStatusCode();
            final String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            LOGGER.debug("Received statusCode {} from {}", statusCode, discoveryEndpointUri);
            if (HttpStatus.SC_OK == statusCode) {
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
                .withHeaders(getHeadersAsStringArray(httpGet.getAllHeaders()))
                .withResponseBody(body)
                .build();
          });
    } catch (final IOException e) {
      if (e instanceof final OAuth2ServiceException oAuth2Exception) {
        throw oAuth2Exception;
      } else {
        throw OAuth2ServiceException.builder(
                "Error retrieving configured oidc endpoints: " + e.getMessage())
            .withUri(discoveryEndpointUri)
            .withHeaders(getHeadersAsStringArray(httpGet.getAllHeaders()))
            .withResponseBody(e.getMessage())
            .build();
      }
    }
  }

  private static String[] getHeadersAsStringArray(final org.apache.http.Header[] headers) {
    return headers != null
        ? Arrays.stream(headers).map(Header::toString).toArray(String[]::new)
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
