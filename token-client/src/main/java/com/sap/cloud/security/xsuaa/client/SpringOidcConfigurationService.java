/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.SpringTokenClientConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import java.net.URI;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

public class SpringOidcConfigurationService implements OidcConfigurationService {
  private final RestOperations restOperations;
  private static final Logger LOGGER =
      LoggerFactory.getLogger(SpringOidcConfigurationService.class);
  private final SpringTokenClientConfiguration config;

  public SpringOidcConfigurationService(@Nonnull final RestOperations restOperations) {
    Assertions.assertNotNull(restOperations, "restOperations must not be null!");
    this.restOperations = restOperations;
    this.config = SpringTokenClientConfiguration.getInstance();
  }

  @Override
  public OAuth2ServiceEndpointsProvider retrieveEndpoints(@Nonnull final URI discoveryEndpointUri)
      throws OAuth2ServiceException {
    Assertions.assertNotNull(discoveryEndpointUri, "discoveryEndpointUri must not be null!");
    return executeRequest(
        discoveryEndpointUri, config.isRetryEnabled() ? config.getMaxRetryAttempts() : 0);
  }

  private OAuth2ServiceEndpointsProvider executeRequest(
      final URI discoveryEndpointUri, final int attemptsLeft) throws OAuth2ServiceException {
    final HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
    LOGGER.debug(
        "Retrieving configured oidc endpoints: {} with headers {} and {} retries left",
        discoveryEndpointUri,
        headers,
        attemptsLeft);
    try {
      final ResponseEntity<String> responseEntity =
          restOperations.exchange(
              discoveryEndpointUri, HttpMethod.GET, new HttpEntity(headers), String.class);
      final int statusCode = responseEntity.getStatusCode().value();
      LOGGER.debug("Received statusCode {}", statusCode);
      if (HttpStatus.OK.value() == statusCode) {
        LOGGER.debug(
            "Successfully retrieved configured oidc endpoints from {}", discoveryEndpointUri);
        return new DefaultOidcConfigurationService.OidcEndpointsProvider(responseEntity.getBody());
      } else if (attemptsLeft > 0 && config.getRetryStatusCodes().contains(statusCode)) {
        LOGGER.warn("Request failed with status {} but is retryable. Retrying...", statusCode);
        pauseBeforeNextAttempt(config.getRetryDelayTime());
        return executeRequest(discoveryEndpointUri, attemptsLeft - 1);
      }
      throw OAuth2ServiceException.builder("Error retrieving configured oidc endpoints")
          .withUri(discoveryEndpointUri)
          .withHeaders(getHeadersAsStringArray(headers))
          .withStatusCode(statusCode)
          .withResponseBody(responseEntity.getBody())
          .build();
    } catch (final HttpClientErrorException ex) {
      throw OAuth2ServiceException.builder("Error retrieving configured oidc endpoints")
          .withUri(discoveryEndpointUri)
          .withHeaders(getHeadersAsStringArray(ex.getResponseHeaders()))
          .withResponseBody(ex.getResponseBodyAsString())
          .withStatusCode(ex.getStatusCode().value())
          .build();
    }
  }

  private void pauseBeforeNextAttempt(final long sleepTime) {
    try {
      LOGGER.info("Retry again in {} ms", sleepTime);
      Thread.sleep(sleepTime);
    } catch (final InterruptedException e) {
      LOGGER.warn("Thread.sleep has been interrupted. Retry starts now.");
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
}
