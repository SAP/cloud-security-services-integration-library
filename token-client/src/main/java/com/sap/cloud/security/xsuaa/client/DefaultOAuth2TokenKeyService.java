/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_OSB_PLAN;

import com.sap.cloud.security.client.ApacheHttpClient4Adapter;
import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.client.HttpClientException;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpClientProvider;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.util.LogSanitizer;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import jakarta.annotation.Nonnull;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultOAuth2TokenKeyService implements OAuth2TokenKeyService {

  private static final String SUCCESS_MESSAGE =
      "Successfully retrieved token keys from {} with params {}.";
  private static final Logger LOGGER = LoggerFactory.getLogger(DefaultOAuth2TokenKeyService.class);
  private final SecurityHttpClient httpClient;
  private final DefaultTokenClientConfiguration config;

  public DefaultOAuth2TokenKeyService() throws HttpClientException {
    httpClient = SecurityHttpClientProvider.createClient(null);
    config = DefaultTokenClientConfiguration.getInstance();
  }

  public DefaultOAuth2TokenKeyService(@Nonnull final SecurityHttpClient httpClient) {
    Assertions.assertNotNull(httpClient, "httpClient is required");
    this.httpClient = httpClient;
    config = DefaultTokenClientConfiguration.getInstance();
  }

  /**
   * @deprecated Since version 4.0.0. Use {@link #DefaultOAuth2TokenKeyService(SecurityHttpClient)} instead.
   *             For migration guidance, see the project documentation on custom HTTP clients.
   * @param httpClient the Apache HttpClient 4 instance
   */
  @Deprecated(since = "4.0.0", forRemoval = true)
  public DefaultOAuth2TokenKeyService(@Nonnull final CloseableHttpClient httpClient) {
    this(new ApacheHttpClient4Adapter(httpClient));
  }

  @Override
  public String retrieveTokenKeys(
      @Nonnull final URI tokenKeysEndpointUri, final Map<String, String> params)
      throws OAuth2ServiceException {
    Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
    validateUri(tokenKeysEndpointUri);
    return executeRequest(
        tokenKeysEndpointUri, params, config.isRetryEnabled() ? config.getMaxRetryAttempts() : 0);
  }

  private void validateUri(final URI uri) throws OAuth2ServiceException {
    String scheme = uri.getScheme();
    if (scheme == null || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
      throw OAuth2ServiceException.builder("Invalid URI scheme. Only HTTP/HTTPS are allowed.")
          .withUri(uri)
          .build();
    }

    String host = uri.getHost();
    if (host == null || host.isEmpty()) {
      throw OAuth2ServiceException.builder("Invalid URI: missing host.")
          .withUri(uri)
          .build();
    }
  }

  private String executeRequest(
      final URI tokenKeysEndpointUri, final Map<String, String> params, final int attemptsLeft)
      throws OAuth2ServiceException {

    SecurityHttpRequest request = createHttpRequest(tokenKeysEndpointUri, params);
    LOGGER.debug(
        "Executing token key retrieval GET request to {} with headers: {} and {} retries left",
        LogSanitizer.sanitize(tokenKeysEndpointUri),
        LogSanitizer.sanitize(request.getHeaders()),
        attemptsLeft);

    try {
      SecurityHttpResponse response = httpClient.execute(request);
      final int statusCode = response.getStatusCode();
      final String body = response.getBody();

      LOGGER.debug("Received statusCode {} from {}", statusCode, LogSanitizer.sanitize(tokenKeysEndpointUri));

      if (statusCode == 200) {
        LOGGER.debug(SUCCESS_MESSAGE, LogSanitizer.sanitize(tokenKeysEndpointUri), LogSanitizer.sanitize(params));
        handleServicePlanFromResponse(response);
        return body;
      } else if (attemptsLeft > 0 && config.getRetryStatusCodes().contains(statusCode)) {
        LOGGER.warn(
            "Request failed with status {} but is retryable. Retrying...", statusCode);
        pauseBeforeNextAttempt(config.getRetryDelayTime());
        return executeRequest(tokenKeysEndpointUri, params, attemptsLeft - 1);
      }

      throw OAuth2ServiceException.builder("Error retrieving token keys.")
          .withUri(tokenKeysEndpointUri)
          .withResponseHeaders(getHeadersAsStringArray(response.getHeaders()))
          .withRequestHeaders(getHeadersAsStringArray(request.getHeaders()))
          .withStatusCode(statusCode)
          .withResponseBody(body)
          .build();

    } catch (final IOException e) {
      if (e instanceof final OAuth2ServiceException oAuth2Exception) {
        throw oAuth2Exception;
      } else {
        throw OAuth2ServiceException.builder("Error retrieving token keys: " + e.getMessage())
            .withUri(tokenKeysEndpointUri)
            .withRequestHeaders(getHeadersAsStringArray(request.getHeaders()))
            .withResponseBody(e.getMessage())
            .build();
      }
    }
  }

  private SecurityHttpRequest createHttpRequest(
      final URI tokenKeysEndpointUri, final Map<String, String> params) {

    Map<String, String> headers = new HashMap<>(params);
    headers.put("User-Agent", HttpClientUtil.getUserAgent());

    return SecurityHttpRequest.newBuilder()
        .method("GET")
        .uri(tokenKeysEndpointUri)
        .headers(headers)
        .build();
  }

  private void pauseBeforeNextAttempt(final long sleepTime) {
    try {
      LOGGER.info("Retry again in {} ms", sleepTime);
      Thread.sleep(sleepTime);
    } catch (final InterruptedException e) {
      LOGGER.warn("Thread.sleep has been interrupted. Retry starts now.");
    }
  }

  private void handleServicePlanFromResponse(final SecurityHttpResponse response) {
    /* This is required for Identity Service App2Service communication. When proof token validation is enabled,
    the response can contain an Identity Service broker plan header whose content needs to be accessible
    on the SecurityContext. */
    String xOsbPlan = response.getHeader(X_OSB_PLAN);
    if (xOsbPlan != null) {
      SecurityContext.setServicePlans(xOsbPlan);
    }
  }

  private static String[] getHeadersAsStringArray(final Map<String, String> headers) {
    return headers != null
        ? headers.entrySet().stream()
            .map(e -> e.getKey() + ": " + e.getValue())
            .toArray(String[]::new)
        : new String[0];
  }
}
