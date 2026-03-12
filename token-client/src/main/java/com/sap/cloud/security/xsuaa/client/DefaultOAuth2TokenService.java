/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

import com.sap.cloud.security.client.ApacheHttpClient4Adapter;
import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;
import com.sap.cloud.security.servlet.MDCHelper;
import com.sap.cloud.security.util.LogSanitizer;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import jakarta.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultOAuth2TokenService extends AbstractOAuth2TokenService {

  private static final Logger LOGGER = LoggerFactory.getLogger(DefaultOAuth2TokenService.class);
  private final SecurityHttpClient httpClient;
  private final DefaultTokenClientConfiguration config =
      DefaultTokenClientConfiguration.getInstance();

  public DefaultOAuth2TokenService(@Nonnull final SecurityHttpClient httpClient) {
    this(httpClient, TokenCacheConfiguration.defaultConfiguration());
  }

  public DefaultOAuth2TokenService(
      @Nonnull final SecurityHttpClient httpClient,
      @Nonnull final TokenCacheConfiguration tokenCacheConfiguration) {
    super(tokenCacheConfiguration);
    Assertions.assertNotNull(httpClient, "http client is required");
    this.httpClient = httpClient;
  }

  /**
   * @deprecated Since version 4.0.0. Use {@link #DefaultOAuth2TokenService(SecurityHttpClient)} instead.
   *             For migration guidance, see the project documentation on custom HTTP clients.
   * @param httpClient the Apache HttpClient 4 instance
   */
  @Deprecated(since = "4.0.0", forRemoval = true)
  public DefaultOAuth2TokenService(@Nonnull final CloseableHttpClient httpClient) {
    this(new ApacheHttpClient4Adapter(httpClient));
  }

  /**
   * @deprecated Since version 4.0.0. Use {@link #DefaultOAuth2TokenService(SecurityHttpClient, TokenCacheConfiguration)} instead.
   *             For migration guidance, see the project documentation on custom HTTP clients.
   * @param httpClient the Apache HttpClient 4 instance
   * @param tokenCacheConfiguration the token cache configuration
   */
  @Deprecated(since = "4.0.0", forRemoval = true)
  public DefaultOAuth2TokenService(
      @Nonnull final CloseableHttpClient httpClient,
      @Nonnull final TokenCacheConfiguration tokenCacheConfiguration) {
    this(new ApacheHttpClient4Adapter(httpClient), tokenCacheConfiguration);
  }

  @Override
  protected OAuth2TokenResponse requestAccessToken(
      final URI tokenUri, final HttpHeaders headers, final Map<String, String> parameters)
      throws OAuth2ServiceException {
    Assertions.assertNotNull(tokenUri, "Token endpoint URI must not be null!");
    return convertToOAuth2TokenResponse(
        executeRequest(
            tokenUri,
            headers,
            parameters,
            config.isRetryEnabled() ? config.getMaxRetryAttempts() : 0));
  }

  private String executeRequest(
      final URI tokenUri,
      final HttpHeaders headers,
      final Map<String, String> parameters,
      final int attemptsLeft)
      throws OAuth2ServiceException {

    logRequest(headers, parameters);

    SecurityHttpRequest request = createHttpRequest(tokenUri, createRequestHeaders(headers), parameters);
    LOGGER.debug(
        "Requesting access token from url {} with headers {} and {} retries left",
        LogSanitizer.sanitize(tokenUri),
        headers,
        attemptsLeft);

    try {
      SecurityHttpResponse response = httpClient.execute(request);
      final int statusCode = response.getStatusCode();
      final String body = response.getBody();

      LOGGER.debug("Received statusCode {} from {}", statusCode, LogSanitizer.sanitize(tokenUri));

      if (statusCode == 200) {
        LOGGER.debug(
            "Successfully retrieved access token from {} with params {}.",
            LogSanitizer.sanitize(tokenUri),
            LogSanitizer.sanitize(parameters));
        return body;
      } else if (attemptsLeft > 0 && config.getRetryStatusCodes().contains(statusCode)) {
        LOGGER.warn(
            "Request failed with status {} but is retryable. Retrying...", statusCode);
        pauseBeforeNextAttempt(config.getRetryDelayTime());
        return executeRequest(tokenUri, headers, parameters, attemptsLeft - 1);
      }

      throw OAuth2ServiceException.builder("Error requesting access token!")
          .withStatusCode(statusCode)
          .withUri(tokenUri)
          .withRequestHeaders(getHeadersAsStringArray(request.getHeaders()))
          .withResponseHeaders(getHeadersAsStringArray(response.getHeaders()))
          .withResponseBody(body)
          .build();

    } catch (final IOException e) {
      if (e instanceof final OAuth2ServiceException oAuth2Exception) {
        throw oAuth2Exception;
      } else {
        throw OAuth2ServiceException.builder("Error requesting access token!")
            .withUri(tokenUri)
            .withRequestHeaders(getHeadersAsStringArray(request.getHeaders()))
            .withResponseBody(e.getMessage())
            .build();
      }
    }
  }

  private HttpHeaders createRequestHeaders(final HttpHeaders headers) {
    final HttpHeaders requestHeaders = new HttpHeaders();
    headers.getHeaders().forEach(h -> requestHeaders.withHeader(h.getName(), h.getValue()));
    requestHeaders.withHeader(MDCHelper.CORRELATION_HEADER, MDCHelper.getOrCreateCorrelationId());
    return requestHeaders;
  }

  private void logRequest(final HttpHeaders headers, final Map<String, String> parameters) {
    LOGGER.debug(
        "access token request {} - {}",
        headers,
        parameters.entrySet().stream()
            .map(
                e -> {
                  if (e.getKey().contains(PASSWORD)
                      || e.getKey().contains(CLIENT_SECRET)
                      || e.getKey().contains(ASSERTION)) {
                    return new AbstractMap.SimpleImmutableEntry<>(e.getKey(), "****");
                  }
                  return e;
                })
            .toList());
  }

  private SecurityHttpRequest createHttpRequest(
      final URI uri, final HttpHeaders headers, final Map<String, String> parameters) {

    Map<String, String> requestHeaders = new HashMap<>();
    headers.getHeaders().forEach(header -> requestHeaders.put(header.getName(), header.getValue()));
    requestHeaders.put("User-Agent", HttpClientUtil.getUserAgent());
    requestHeaders.put("Content-Type", "application/x-www-form-urlencoded");

    // Build form-encoded body
    String body = parameters.entrySet().stream()
        .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" +
                  URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(Collectors.joining("&"));

    return SecurityHttpRequest.newBuilder()
        .method("POST")
        .uri(uri)
        .headers(requestHeaders)
        .body(body.getBytes(StandardCharsets.UTF_8))
        .build();
  }

  private OAuth2TokenResponse convertToOAuth2TokenResponse(final String responseBody)
      throws OAuth2ServiceException {
    final Map<String, Object> accessTokenMap = new JSONObject(responseBody).toMap();
    final String accessToken = getParameter(accessTokenMap, ACCESS_TOKEN);
    final String refreshToken = getParameter(accessTokenMap, REFRESH_TOKEN);
    final String expiresIn = getParameter(accessTokenMap, EXPIRES_IN);
    final String tokenType = getParameter(accessTokenMap, TOKEN_TYPE);
    return new OAuth2TokenResponse(
        accessToken, convertExpiresInToLong(expiresIn), refreshToken, tokenType);
  }

  private Long convertExpiresInToLong(final String expiresIn) throws OAuth2ServiceException {
    try {
      return Long.parseLong(expiresIn);
    } catch (final NumberFormatException e) {
      throw new OAuth2ServiceException(
					"Cannot convert expires_in from response (%s) to long".formatted(expiresIn));
    }
  }

  private String getParameter(final Map<String, Object> accessTokenMap, final String key) {
    return String.valueOf(accessTokenMap.get(key));
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
}
