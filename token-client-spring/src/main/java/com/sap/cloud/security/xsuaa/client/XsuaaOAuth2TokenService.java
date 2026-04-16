/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.servlet.MDCHelper;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import java.net.URI;
import java.util.Map;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;

/** Implementation for Spring applications, that uses {@link RestOperations}. */
public class XsuaaOAuth2TokenService extends AbstractOAuth2TokenService {

  private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaOAuth2TokenService.class);
  private final RestOperations restOperations;
  private final DefaultTokenClientConfiguration config;

  public XsuaaOAuth2TokenService(@Nonnull final RestOperations restOperations) {
    this(restOperations, TokenCacheConfiguration.defaultConfiguration());
  }

  public XsuaaOAuth2TokenService(
      @Nonnull final RestOperations restOperations,
      @Nonnull final TokenCacheConfiguration tokenCacheConfiguration) {
    super(tokenCacheConfiguration);
    assertNotNull(restOperations, "restOperations is required");
    this.restOperations = restOperations;
    this.config = DefaultTokenClientConfiguration.getInstance();
  }

  @Override
  protected OAuth2TokenResponse requestAccessToken(
      @Nonnull final URI tokenEndpointUri,
      final HttpHeaders headers,
      final Map<String, String> parameters)
      throws OAuth2ServiceException {
    assertNotNull(tokenEndpointUri, "Token endpoint URI must not be null!");
    return executeRequest(
        tokenEndpointUri,
        headers,
        parameters,
        config.isRetryEnabled() ? config.getMaxRetryAttempts() : 0);
  }

  private OAuth2TokenResponse executeRequest(
      final URI tokenEndpointUri,
      final HttpHeaders headers,
      final Map<String, String> parameters,
      final int attemptsLeft)
      throws OAuth2ServiceException {

    final URI requestUri = createRequestUri(tokenEndpointUri);
    final org.springframework.http.HttpHeaders springHeaders = createSpringHeaders(headers);
    final HttpEntity<MultiValueMap<String, String>> requestEntity =
        new HttpEntity<>(copyIntoForm(parameters), springHeaders);
    LOGGER.debug(
        "Requesting access token from url='{}' with headers={} and {} retries left",
        requestUri,
        springHeaders,
        attemptsLeft);
    try {
      final ResponseEntity<Map> responseEntity =
          restOperations.postForEntity(requestUri, requestEntity, Map.class);
      final int statusCode = responseEntity.getStatusCode().value();
      LOGGER.debug("Received statusCode {}", statusCode);
      @SuppressWarnings("unchecked")
      final Map<String, String> accessTokenMap = responseEntity.getBody();
      if (HttpStatus.OK.value() == statusCode && accessTokenMap != null) {
        LOGGER.debug(
            "Successfully retrieved access token from url='{}'with params {}.",
            requestUri,
            parameters);
        return processResponseBody(accessTokenMap);
      } else if (attemptsLeft > 0 && config.getRetryStatusCodes().contains(statusCode)) {
        LOGGER.warn("Request failed with status {} but is retryable. Retrying...", statusCode);
        pauseBeforeNextAttempt(config.getRetryDelayTime());
        return executeRequest(tokenEndpointUri, headers, parameters, attemptsLeft - 1);
      }
      throw OAuth2ServiceException.builder("Server error while obtaining access token from XSUAA!")
          .withUri(requestUri)
          .withRequestHeaders(getHeadersAsStringArray(springHeaders))
          .withResponseHeaders(getHeadersAsStringArray(requestEntity.getHeaders()))
          .withStatusCode(statusCode)
          .withResponseBody(accessTokenMap != null ? accessTokenMap.toString() : null)
          .build();
    } catch (final HttpClientErrorException clientEx) {
      throw OAuth2ServiceException.builder(
              "Client error retrieving JWT token. Call to XSUAA was not successful!")
          .withUri(requestUri)
          .withRequestHeaders(getHeadersAsStringArray(springHeaders))
          .withStatusCode(clientEx.getStatusCode().value())
          .withResponseBody(clientEx.getResponseBodyAsString())
          .build();
    } catch (final HttpServerErrorException serverEx) {
      throw OAuth2ServiceException.builder("Server error while obtaining access token from XSUAA!")
          .withUri(requestUri)
          .withRequestHeaders(getHeadersAsStringArray(springHeaders))
          .withStatusCode(serverEx.getStatusCode().value())
          .withResponseBody(serverEx.getResponseBodyAsString())
          .build();
    } catch (final ResourceAccessException resourceEx) {
      throw OAuth2ServiceException.builder(
              "RestClient isn't configured properly - Error while obtaining access token from XSUAA!")
          .withUri(requestUri)
          .withRequestHeaders(getHeadersAsStringArray(springHeaders))
          .withResponseBody(resourceEx.getLocalizedMessage())
          .build();
    }
  }

  private static String[] getHeadersAsStringArray(
      final org.springframework.http.HttpHeaders headers) {
    return headers != null
        ? headers.entrySet().stream()
            .map(e -> e.getKey() + ": " + String.join(",", e.getValue()))
            .toArray(String[]::new)
        : new String[0];
  }

  /**
   * Creates a copy of the given map or a new empty map of type MultiValueMap.
   *
   * @return a new @link{MultiValueMap} that contains all entries of the optional map.
   */
  private MultiValueMap<String, String> copyIntoForm(final Map<String, String> parameters) {
    final MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
    if (parameters != null) {
      parameters.forEach(formData::add);
    }
    return formData;
  }

  private OAuth2TokenResponse processResponseBody(final Map<String, String> accessTokenMap)
      throws OAuth2ServiceException {
    final String accessToken = accessTokenMap.get(ACCESS_TOKEN);
    final long expiresIn;
    try {
      expiresIn = Long.parseLong(String.valueOf(accessTokenMap.get(EXPIRES_IN)));
    } catch (final NumberFormatException e) {
      LOGGER.error("Invalid expires_in value: {}", accessTokenMap.get(EXPIRES_IN), e);
      throw OAuth2ServiceException.builder("Invalid expires_in value")
          .withResponseBody(e.getLocalizedMessage())
          .build();
    }
    final String refreshToken = accessTokenMap.get(REFRESH_TOKEN);
    final String tokenType = accessTokenMap.get(TOKEN_TYPE);
    return new OAuth2TokenResponse(accessToken, expiresIn, refreshToken, tokenType);
  }

  private URI createRequestUri(final URI tokenEndpointUri) {
    return UriComponentsBuilder.fromUri(tokenEndpointUri).build().encode().toUri();
  }

  private org.springframework.http.HttpHeaders createSpringHeaders(final HttpHeaders headers) {
    final org.springframework.http.HttpHeaders springHeaders =
        new org.springframework.http.HttpHeaders();
    headers.getHeaders().forEach(h -> springHeaders.add(h.getName(), h.getValue()));
    springHeaders.add(MDCHelper.CORRELATION_HEADER, MDCHelper.getOrCreateCorrelationId());
    springHeaders.add(
        org.springframework.http.HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
    return springHeaders;
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
