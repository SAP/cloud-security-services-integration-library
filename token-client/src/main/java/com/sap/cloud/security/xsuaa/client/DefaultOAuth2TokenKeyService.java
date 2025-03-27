/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_OSB_PLAN;

import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import javax.annotation.Nonnull;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultOAuth2TokenKeyService implements OAuth2TokenKeyService {

  private static final String SUCCESS_MESSAGE =
      "Successfully retrieved token keys from {} with params {}.";
  private static final Logger LOGGER = LoggerFactory.getLogger(DefaultOAuth2TokenKeyService.class);
  private final CloseableHttpClient httpClient;
  private final DefaultTokenClientConfiguration config;

  public DefaultOAuth2TokenKeyService() {
    httpClient = HttpClientFactory.create(null);
    config = DefaultTokenClientConfiguration.getInstance();
  }

  public DefaultOAuth2TokenKeyService(@Nonnull final CloseableHttpClient httpClient) {
    Assertions.assertNotNull(httpClient, "httpClient is required");
    this.httpClient = httpClient;
    config = DefaultTokenClientConfiguration.getInstance();
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
    final HttpUriRequest request = getHttpUriRequest(tokenKeysEndpointUri, params);
    LOGGER.debug(
        "Executing token key retrieval GET request to {} with headers: {} and {} retries left",
        tokenKeysEndpointUri,
        request.getAllHeaders(),
        attemptsLeft);
    try {
      return httpClient.execute(
          request,
          response -> {
            final int statusCode = response.getStatusLine().getStatusCode();
            final String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            LOGGER.debug("Received statusCode {} from {}", statusCode, tokenKeysEndpointUri);

            if (HttpStatus.SC_OK == statusCode) {
              LOGGER.debug(SUCCESS_MESSAGE, tokenKeysEndpointUri, params);
              handleServicePlanFromResponse(response);
              return body;
            } else if (attemptsLeft > 0 && config.getRetryStatusCodes().contains(statusCode)) {
              LOGGER.warn(
                  "Request failed with status {} but is retryable. Retrying...", statusCode);
              pauseBeforeNextAttempt(config.getRetryDelayTime());
              return executeRequest(tokenKeysEndpointUri, params, attemptsLeft - 1);
            }
            throw OAuth2ServiceException.builder(
                    "Error retrieving token keys. Request headers "
                        + Arrays.stream(request.getAllHeaders()).toList())
                .withUri(tokenKeysEndpointUri)
                .withHeaders(
                    response.getAllHeaders() != null
                        ? Arrays.stream(response.getAllHeaders())
                            .map(Header::toString)
                            .toArray(String[]::new)
                        : null)
                .withStatusCode(statusCode)
                .withResponseBody(body)
                .build();
          });
    } catch (final IOException e) {
      if (e instanceof final OAuth2ServiceException oAuth2Exception) {
        throw oAuth2Exception;
      } else {
        throw new OAuth2ServiceException("Error retrieving token keys: " + e.getMessage());
      }
    }
  }

  private HttpUriRequest getHttpUriRequest(
      final URI tokenKeysEndpointUri, final Map<String, String> params) {
    final HttpUriRequest request = new HttpGet(tokenKeysEndpointUri);
    for (final Map.Entry<String, String> p : params.entrySet()) {
      request.addHeader(p.getKey(), p.getValue());
    }
    request.addHeader(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
    return request;
  }

  private void pauseBeforeNextAttempt(final long sleepTime) {
    try {
      LOGGER.info("Retry again in {} ms", sleepTime);
      Thread.sleep(sleepTime);
    } catch (final InterruptedException e) {
      LOGGER.warn("Thread.sleep has been interrupted. Retry starts now.");
    }
  }

  private void handleServicePlanFromResponse(final HttpResponse response) {
    /* This is required for Identity Service App2Service communication. When proof token validation is enabled,
    the response can contain an Identity Service broker plan header whose content needs to be accessible
    on the SecurityContext. */
    if (response.containsHeader(X_OSB_PLAN)) {
      final String xOsbPlan = response.getFirstHeader(X_OSB_PLAN).getValue();
      if (xOsbPlan != null) {
        SecurityContext.setServicePlans(xOsbPlan);
      }
    }
  }
}
