/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static org.apache.http.HttpHeaders.USER_AGENT;

import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.servlet.MDCHelper;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultOAuth2TokenService extends AbstractOAuth2TokenService {

  private static final Logger LOGGER = LoggerFactory.getLogger(DefaultOAuth2TokenService.class);
  private final CloseableHttpClient httpClient;
  private final DefaultTokenClientConfiguration config;

  public DefaultOAuth2TokenService(@Nonnull final CloseableHttpClient httpClient) {
    this(httpClient, TokenCacheConfiguration.defaultConfiguration());
  }

  public DefaultOAuth2TokenService(
      @Nonnull final CloseableHttpClient httpClient,
      @Nonnull final TokenCacheConfiguration tokenCacheConfiguration) {
    super(tokenCacheConfiguration);
    Assertions.assertNotNull(httpClient, "http client is required");
    this.httpClient = httpClient;
    this.config = DefaultTokenClientConfiguration.getInstance();
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
    final HttpPost httpPost = createHttpPost(tokenUri, createRequestHeaders(headers), parameters);
    LOGGER.debug(
        "Requesting access token from url {} with headers {} and {} retries left",
        tokenUri,
        headers,
        attemptsLeft);
    try {
      return httpClient.execute(
          httpPost,
          response -> {
            final int statusCode = response.getStatusLine().getStatusCode();
            final String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            LOGGER.debug("Received statusCode {} from {}", statusCode, tokenUri);
            if (HttpStatus.SC_OK == statusCode) {
              LOGGER.debug(
                  "Successfully retrieved access token from {} with params {}.",
                  tokenUri,
                  parameters);
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
                .withRequestHeaders(getHeadersAsStringArray(httpPost.getAllHeaders()))
                .withResponseHeaders(getHeadersAsStringArray(response.getAllHeaders()))
                .withResponseBody(body)
                .build();
          });
    } catch (final IOException e) {
      if (e instanceof final OAuth2ServiceException oAuth2Exception) {
        throw oAuth2Exception;
      } else {
        throw OAuth2ServiceException.builder("Error requesting access token!")
            .withUri(tokenUri)
            .withRequestHeaders(getHeadersAsStringArray(httpPost.getAllHeaders()))
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

  private HttpPost createHttpPost(
      final URI uri, final HttpHeaders headers, final Map<String, String> parameters)
      throws OAuth2ServiceException {
    final HttpPost httpPost = new HttpPost(uri);
    headers.getHeaders().forEach(header -> httpPost.setHeader(header.getName(), header.getValue()));
    final List<BasicNameValuePair> basicNameValuePairs =
        parameters.entrySet().stream()
            .map(entry -> new BasicNameValuePair(entry.getKey(), entry.getValue()))
            .toList();
    try {
      httpPost.setEntity(new UrlEncodedFormEntity(basicNameValuePairs));
      httpPost.addHeader(USER_AGENT, HttpClientUtil.getUserAgent());
    } catch (final UnsupportedEncodingException e) {
      throw new OAuth2ServiceException("Unexpected error parsing URI: " + e.getMessage());
    }
    logRequest(headers, parameters);
    return httpPost;
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
          String.format("Cannot convert expires_in from response (%s) to long", expiresIn));
    }
  }

  private String getParameter(final Map<String, Object> accessTokenMap, final String key) {
    return String.valueOf(accessTokenMap.get(key));
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
}
