/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.SpringTokenClientConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import io.micrometer.common.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestOperations;

import javax.annotation.Nonnull;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.RETRY_MAX_DELAY_TIME;
import static org.springframework.http.HttpMethod.GET;

public class SpringOAuth2TokenKeyService implements OAuth2TokenKeyService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SpringOAuth2TokenKeyService.class);
    private final List<Integer> retryableStatusCodes;
    private final SpringTokenClientConfiguration config;
    private final RestOperations restOperations;

    public SpringOAuth2TokenKeyService(@Nonnull final RestOperations restOperations) {
        Assertions.assertNotNull(restOperations, "restOperations must not be null!");
        this.restOperations = restOperations;
        config = SpringTokenClientConfiguration.getConfig();
        final String statusCodes = config.getRetryStatusCodes();
        this.retryableStatusCodes = Arrays.stream(statusCodes.split(","))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .map(Integer::parseInt)
                .toList();
    }

    private static HttpHeaders getHttpHeaders(final Map<String, String> params) {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
        for (final Map.Entry<String, String> p : params.entrySet()) {
            headers.set(p.getKey(), p.getValue());
        }
        return headers;
    }

    private static void pauseBeforeNextAttempt(final long sleepTime) {
        if (sleepTime > RETRY_MAX_DELAY_TIME) {
            LOGGER.warn("Retry delay time of {} ms exceeded maximum threshold of {} ms", sleepTime, RETRY_MAX_DELAY_TIME);
            pauseBeforeNextAttempt(RETRY_MAX_DELAY_TIME);
        }
        try {
            Thread.sleep(sleepTime);
        } catch (final InterruptedException e) {
            LOGGER.warn("Thread.sleep has been interrupted. Retry starts now.");
        }
    }

    @Override
    public String retrieveTokenKeys(@Nonnull final URI tokenKeysEndpointUri, final Map<String, String> params)
            throws OAuth2ServiceException {
        Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
        return executeRequest(tokenKeysEndpointUri, params, config.isRetryEnabled() ? config.getMaxRetryAttempts() : 0);
    }

    private String executeRequest(final URI tokenKeysEndpointUri, final Map<String, String> params, final int attemptsLeft)
            throws OAuth2ServiceException {
        if (attemptsLeft < 0) {
            throw new OAuth2ServiceException("Max retry attempts reached for token keys endpoint: " + tokenKeysEndpointUri);
        }
        final HttpHeaders headers = getHttpHeaders(params);
        try {
            final ResponseEntity<String> response = restOperations.exchange(
                    tokenKeysEndpointUri, GET, new HttpEntity<>(headers), String.class);
            final int statusCode = response.getStatusCode().value();
            LOGGER.debug("Received statusCode {}", statusCode);

            if (HttpStatus.OK.value() == statusCode) {
                LOGGER.debug("Successfully retrieved token keys from {} for params '{}'", tokenKeysEndpointUri, params);
                return response.getBody();
            } else if (attemptsLeft > 0 && retryableStatusCodes.contains(statusCode)) {
                LOGGER.warn("Request failed with status {} but is retryable. Retrying...", statusCode);
                pauseBeforeNextAttempt(config.getRetryDelayTime());
                return executeRequest(tokenKeysEndpointUri, params, attemptsLeft - 1);
            }
            throw OAuth2ServiceException.builder(
                            "Error retrieving token keys. Request headers [" + headers.entrySet().stream()
                                    .map(h -> h.getKey() + ": " + String.join(",", h.getValue()))
                                    .collect(Collectors.joining(", ")) + "]")
                    .withUri(tokenKeysEndpointUri)
                    .withHeaders(!response.getHeaders().isEmpty() ? response.getHeaders().entrySet().stream().map(
                                    h -> h.getKey() + ": " + String.join(",", h.getValue()))
                            .toArray(String[]::new) : null)
                    .withStatusCode(response.getStatusCode().value())
                    .withResponseBody(response.getBody())
                    .build();
        } catch (final HttpStatusCodeException ex) {
            throw OAuth2ServiceException.builder(
                            "Error retrieving token keys. Request headers [" + headers.entrySet().stream()
                                    .map(h -> h.getKey() + ": " + String.join(",", h.getValue())))
                    .withUri(tokenKeysEndpointUri)
                    .withHeaders(ex.getResponseHeaders() != null ? ex.getResponseHeaders().entrySet().stream().map(
                                    h -> h.getKey() + ": " + String.join(",", h.getValue()))
                            .toArray(String[]::new) : null)
                    .withStatusCode(ex.getStatusCode().value())
                    .withResponseBody(ex.getResponseBodyAsString())
                    .build();
        } catch (final Exception e) {
            if (e instanceof final OAuth2ServiceException oAuth2ServiceException) {
                throw oAuth2ServiceException;
            } else {
                throw OAuth2ServiceException.builder("Unexpected error retrieving token keys: " + e.getMessage())
                        .withUri(tokenKeysEndpointUri)
                        .build();
            }
        }
    }
}
