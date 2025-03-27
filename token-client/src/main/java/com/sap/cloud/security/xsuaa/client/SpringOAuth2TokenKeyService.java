/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static org.springframework.http.HttpMethod.GET;

import com.sap.cloud.security.client.SpringTokenClientConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestOperations;

public class SpringOAuth2TokenKeyService implements OAuth2TokenKeyService {

  private static final Logger LOGGER = LoggerFactory.getLogger(SpringOAuth2TokenKeyService.class);
  private final SpringTokenClientConfiguration config;
  private final RestOperations restOperations;

  public SpringOAuth2TokenKeyService(@Nonnull final RestOperations restOperations) {
    Assertions.assertNotNull(restOperations, "restOperations must not be null!");
    this.restOperations = restOperations;
    config = SpringTokenClientConfiguration.getInstance();
  }

  @Override
  public String retrieveTokenKeys(
      @Nonnull final URI tokenKeysEndpointUri, final Map<String, String> params)
      throws OAuth2ServiceException {
    Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
    return executeRequest(
        tokenKeysEndpointUri, params, config.isRetryEnabled() ? config.getMaxRetryAttempts() : 0);
  }

  private String executeRequest(
      final URI tokenKeysEndpointUri, final Map<String, String> params, final int attemptsLeft)
      throws OAuth2ServiceException {
    final HttpHeaders headers = getHttpHeaders(params);
    try {
      final ResponseEntity<String> response =
          restOperations.exchange(
              tokenKeysEndpointUri, GET, new HttpEntity<>(headers), String.class);
      final int statusCode = response.getStatusCode().value();
      LOGGER.debug("Received statusCode {}", statusCode);

      if (HttpStatus.OK.value() == statusCode) {
        LOGGER.debug(
            "Successfully retrieved token keys from {} for params '{}'",
            tokenKeysEndpointUri,
            params);
        return response.getBody();
      } else if (attemptsLeft > 0 && config.getRetryStatusCodes().contains(statusCode)) {
        LOGGER.warn("Request failed with status {} but is retryable. Retrying...", statusCode);
        pauseBeforeNextAttempt(config.getRetryDelayTime());
        return executeRequest(tokenKeysEndpointUri, params, attemptsLeft - 1);
      }
      throw OAuth2ServiceException.builder(
              "Error retrieving token keys. Request headers ["
                  + headers.entrySet().stream()
                      .map(h -> h.getKey() + ": " + String.join(",", h.getValue()))
                      .collect(Collectors.joining(", "))
                  + "]")
          .withUri(tokenKeysEndpointUri)
          .withHeaders(
              !response.getHeaders().isEmpty()
                  ? response.getHeaders().entrySet().stream()
                      .map(h -> h.getKey() + ": " + String.join(",", h.getValue()))
                      .toArray(String[]::new)
                  : new String[0])
          .withStatusCode(response.getStatusCode().value())
          .withResponseBody(response.getBody())
          .build();
    } catch (final HttpStatusCodeException ex) {
      throw OAuth2ServiceException.builder(
              "Error retrieving token keys. Request headers ["
                  + headers.entrySet().stream()
                      .map(h -> h.getKey() + ": " + String.join(",", h.getValue()))
                      .collect(Collectors.joining(", "))
                  + "]")
          .withUri(tokenKeysEndpointUri)
          .withHeaders(
              ex.getResponseHeaders() != null && !ex.getResponseHeaders().isEmpty()
                  ? ex.getResponseHeaders().entrySet().stream()
                      .map(h -> h.getKey() + ": " + String.join(",", h.getValue()))
                      .toArray(String[]::new)
                  : new String[0])
          .withStatusCode(ex.getStatusCode().value())
          .withResponseBody(ex.getResponseBodyAsString())
          .build();
    } catch (final Exception e) {
      if (e instanceof final OAuth2ServiceException oAuth2ServiceException) {
        throw oAuth2ServiceException;
      } else {
        throw OAuth2ServiceException.builder(
                "Unexpected error retrieving token keys: " + e.getMessage())
            .withUri(tokenKeysEndpointUri)
            .build();
      }
    }
  }

  private HttpHeaders getHttpHeaders(final Map<String, String> params) {
    final HttpHeaders headers = new HttpHeaders();
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    headers.set(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
    for (final Map.Entry<String, String> p : params.entrySet()) {
      headers.set(p.getKey(), p.getValue());
    }
    return headers;
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
